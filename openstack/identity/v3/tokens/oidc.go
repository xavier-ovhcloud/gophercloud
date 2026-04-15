// Package tokens provides OIDC authentication support for OpenStack Keystone v3.
//
// This file implements the Go equivalent of keystoneauth1/identity/v3/oidc.py,
// covering all OIDC auth flows:
//
//   - OidcClientCredentials  (v3oidcclientcredentials)
//   - OidcPassword           (v3oidcpassword)
//   - OidcAuthorizationCode  (v3oidcauthcode)
//   - OidcAccessToken        (v3oidcaccesstoken)
//
// Reference: https://github.com/openstack/keystoneauth/blob/master/keystoneauth1/identity/v3/oidc.py
package tokens

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/utils"
)

// oidcDiscoveryDocument holds the relevant fields from an OIDC discovery endpoint.
// See: https://openid.net/specs/openid-connect-discovery-1_0.html
type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	JWKsURI               string `json:"jwks_uri"`
}

// OIDCTokenResponse is the response from an OIDC token endpoint.
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// AccessTokenType defines which token from the OIDC response to use
// when presenting to Keystone's federation endpoint.
type AccessTokenType string

const (
	// AccessTokenTypeAccess uses the access_token field (default for most IdPs).
	AccessTokenTypeAccess AccessTokenType = "access_token"
	// AccessTokenTypeID uses the id_token field (required by OVHcloud IAM).
	AccessTokenTypeID AccessTokenType = "id_token"
)

// OIDCBase holds common fields shared by all OIDC auth flows.
type OIDCBase struct {
	// IdentityEndpoint is the Keystone auth URL (e.g. https://auth.cloud.ovh.net/v3).
	IdentityEndpoint string

	// IdentityProvider is the name of the identity provider configured in Keystone
	// (e.g. "ovhcloud-emea", "atmosphere").
	IdentityProvider string

	// Protocol is the federation protocol registered in Keystone (typically "openid").
	Protocol string

	// DiscoveryEndpoint is the OIDC discovery URL (.well-known/openid-configuration).
	// Either DiscoveryEndpoint or TokenEndpoint must be set.
	DiscoveryEndpoint string

	// TokenEndpoint overrides discovery and directly specifies the OIDC token URL.
	TokenEndpoint string

	// ClientID is the OIDC client ID.
	ClientID string

	// ClientSecret is the OIDC client secret.
	ClientSecret string

	// Scopes is the list of OIDC scopes to request.
	// Defaults to ["openid"] if empty.
	Scopes []string

	// AccessTokenType controls which token from the OIDC response is sent to Keystone.
	// Defaults to AccessTokenTypeAccess.
	AccessTokenType AccessTokenType

	// ProjectID scopes the resulting Keystone token to a specific project.
	// Either ProjectID or ProjectName + ProjectDomainID must be set.
	ProjectID string

	// ProjectName scopes the resulting Keystone token by project name.
	ProjectName string

	// ProjectDomainID is the domain owning ProjectName.
	ProjectDomainID string

	// DomainID scopes the resulting Keystone token to a domain (mutually exclusive with project scope).
	DomainID string

	// AllowReauth controls whether gophercloud will automatically reauthenticate
	// when the token expires.
	AllowReauth bool

	// httpClient is used internally for OIDC requests (not Keystone).
	// Defaults to a standard http.Client with a 30s timeout.
	httpClient *http.Client
}

func (o *OIDCBase) client() *http.Client {
	if o.httpClient != nil {
		return o.httpClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (o *OIDCBase) scopes() string {
	if len(o.Scopes) == 0 {
		return "openid"
	}
	return strings.Join(o.Scopes, " ")
}

func (o *OIDCBase) accessTokenType() AccessTokenType {
	if o.AccessTokenType == "" {
		return AccessTokenTypeAccess
	}
	return o.AccessTokenType
}

// resolveTokenEndpoint fetches the OIDC discovery document and returns the token_endpoint.
// If TokenEndpoint is already set, it is returned directly without a network call.
func (o *OIDCBase) resolveTokenEndpoint(ctx context.Context) (string, error) {
	if o.TokenEndpoint != "" {
		return o.TokenEndpoint, nil
	}
	if o.DiscoveryEndpoint == "" {
		return "", fmt.Errorf("oidc: either TokenEndpoint or DiscoveryEndpoint must be set")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.DiscoveryEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("oidc: building discovery request: %w", err)
	}

	resp, err := o.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc: fetching discovery document from %s: %w", o.DiscoveryEndpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc: discovery endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("oidc: reading discovery response: %w", err)
	}

	var doc oidcDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("oidc: parsing discovery document: %w", err)
	}
	if doc.TokenEndpoint == "" {
		return "", fmt.Errorf("oidc: discovery document missing token_endpoint")
	}
	return doc.TokenEndpoint, nil
}

// postToTokenEndpoint sends a POST request to the OIDC token endpoint with
// the given form values and returns the parsed response.
func (o *OIDCBase) postToTokenEndpoint(ctx context.Context, tokenEndpoint string, values url.Values) (*OIDCTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
		strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: posting to token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oidc: reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("oidc: parsing token response: %w", err)
	}
	return &tokenResp, nil
}

// selectToken picks the correct token from the OIDC response based on AccessTokenType.
func (o *OIDCBase) selectToken(tokenResp *OIDCTokenResponse) (string, error) {
	switch o.accessTokenType() {
	case AccessTokenTypeID:
		if tokenResp.IDToken == "" {
			return "", fmt.Errorf("oidc: id_token not present in response (IdP may not support it)")
		}
		return tokenResp.IDToken, nil
	case AccessTokenTypeAccess:
		if tokenResp.AccessToken == "" {
			return "", fmt.Errorf("oidc: access_token not present in response")
		}
		return tokenResp.AccessToken, nil
	default:
		return "", fmt.Errorf("oidc: unknown access_token_type %q", o.accessTokenType())
	}
}

// federationURL builds the Keystone OS-FEDERATION URL for this IdP and protocol.
func (o *OIDCBase) federationURL() string {
	base := strings.TrimRight(o.IdentityEndpoint, "/")
	return fmt.Sprintf("%s/OS-FEDERATION/identity_providers/%s/protocols/%s/auth",
		base, o.IdentityProvider, o.Protocol)
}

// exchangeTokenWithKeystone sends the OIDC bearer token to the Keystone
// federation endpoint and returns an unscoped Keystone token.
func (o *OIDCBase) exchangeTokenWithKeystone(ctx context.Context, bearerToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.federationURL(), nil)
	if err != nil {
		return "", fmt.Errorf("oidc: building Keystone federation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc: posting to Keystone federation endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("oidc: Keystone federation returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	unscopedToken := resp.Header.Get("X-Subject-Token")
	if unscopedToken == "" {
		return "", fmt.Errorf("oidc: Keystone federation response missing X-Subject-Token header")
	}
	return unscopedToken, nil
}

// scopeToken exchanges the unscoped Keystone token for a project- or domain-scoped token.
func (o *OIDCBase) scopeToken(ctx context.Context, unscopedToken string) (string, error) {
	base := strings.TrimRight(o.IdentityEndpoint, "/")
	endpoint := base + "/auth/tokens"

	scope := map[string]interface{}{}
	if o.ProjectID != "" {
		scope["project"] = map[string]interface{}{"id": o.ProjectID}
	} else if o.ProjectName != "" {
		scope["project"] = map[string]interface{}{
			"name":   o.ProjectName,
			"domain": map[string]interface{}{"id": o.ProjectDomainID},
		}
	} else if o.DomainID != "" {
		scope["domain"] = map[string]interface{}{"id": o.DomainID}
	} else {
		// No scope requested — return the unscoped token as-is.
		return unscopedToken, nil
	}

	payload := map[string]interface{}{
		"auth": map[string]interface{}{
			"identity": map[string]interface{}{
				"methods": []string{"token"},
				"token":   map[string]interface{}{"id": unscopedToken},
			},
			"scope": scope,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("oidc: marshalling scope request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("oidc: building scope request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", unscopedToken)

	resp, err := o.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc: posting to Keystone auth/tokens: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("oidc: token scoping returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	scopedToken := resp.Header.Get("X-Subject-Token")
	if scopedToken == "" {
		return "", fmt.Errorf("oidc: token scoping response missing X-Subject-Token header")
	}
	return scopedToken, nil
}

// createProviderClient builds a gophercloud ProviderClient authenticated
// with the given scoped Keystone token. If AllowReauth is true, reauthFunc
// is called to obtain a fresh token when the current one expires.
func (o *OIDCBase) createProviderClient(_ context.Context, scopedToken string, reauthFunc func(context.Context) (string, error)) (*gophercloud.ProviderClient, error) {
	base, err := utils.BaseEndpoint(o.IdentityEndpoint)
	if err != nil {
		return nil, fmt.Errorf("oidc: creating provider client: %w", err)
	}

	pc := new(gophercloud.ProviderClient)
	pc.IdentityBase = gophercloud.NormalizeURL(base)
	pc.IdentityEndpoint = gophercloud.NormalizeURL(o.IdentityEndpoint)
	pc.UseTokenLock()
	pc.SetToken(scopedToken)
	if o.AllowReauth && reauthFunc != nil {
		pc.ReauthFunc = func(ctx context.Context) error {
			newToken, err := reauthFunc(ctx)
			if err != nil {
				return err
			}
			pc.SetToken(newToken)
			return nil
		}
	}

	return pc, nil
}

// completeAuth runs steps 2 and 3: federation exchange + scoping.
func (o *OIDCBase) completeAuth(ctx context.Context, bearerToken string) (string, error) {
	unscopedToken, err := o.exchangeTokenWithKeystone(ctx, bearerToken)
	if err != nil {
		return "", err
	}
	return o.scopeToken(ctx, unscopedToken)
}

// --- OidcClientCredentials ---------------------------------------------------

// OidcClientCredentials authenticates using the OAuth2 Client Credentials flow
// (grant_type=client_credentials).
//
// This corresponds to keystoneauth1's OidcClientCredentials / v3oidcclientcredentials.
// Commonly used for machine-to-machine auth, e.g. OVHcloud IAM service accounts.
type OidcClientCredentials struct {
	OIDCBase
}

// GetToken fetches an OIDC access/id_token using client credentials, then
// exchanges it with Keystone to obtain a scoped token.
func (o *OidcClientCredentials) GetToken(ctx context.Context) (string, error) {
	tokenEndpoint, err := o.resolveTokenEndpoint(ctx)
	if err != nil {
		return "", err
	}

	values := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {o.ClientID},
		"client_secret": {o.ClientSecret},
		"scope":         {o.scopes()},
	}

	oidcResp, err := o.postToTokenEndpoint(ctx, tokenEndpoint, values)
	if err != nil {
		return "", err
	}

	bearerToken, err := o.selectToken(oidcResp)
	if err != nil {
		return "", err
	}

	return o.completeAuth(ctx, bearerToken)
}

// AuthenticatedClient returns a gophercloud ProviderClient authenticated
// via the OIDC Client Credentials flow.
func (o *OidcClientCredentials) AuthenticatedClient(ctx context.Context) (*gophercloud.ProviderClient, error) {
	token, err := o.GetToken(ctx)
	if err != nil {
		return nil, err
	}
	return o.createProviderClient(ctx, token, o.GetToken)
}

// --- OidcPassword ------------------------------------------------------------

// OidcPassword authenticates using the OIDC Resource Owner Password Credentials
// flow (grant_type=password).
//
// This corresponds to keystoneauth1's OidcPassword / v3oidcpassword.
// Note: many modern IdPs disable this flow for security reasons.
type OidcPassword struct {
	OIDCBase

	// Username is the end-user's username at the IdP.
	Username string

	// Password is the end-user's password at the IdP.
	Password string
}

// GetToken fetches an OIDC token using the password grant, then exchanges
// it with Keystone.
func (o *OidcPassword) GetToken(ctx context.Context) (string, error) {
	tokenEndpoint, err := o.resolveTokenEndpoint(ctx)
	if err != nil {
		return "", err
	}

	values := url.Values{
		"grant_type":    {"password"},
		"client_id":     {o.ClientID},
		"client_secret": {o.ClientSecret},
		"username":      {o.Username},
		"password":      {o.Password},
		"scope":         {o.scopes()},
	}

	oidcResp, err := o.postToTokenEndpoint(ctx, tokenEndpoint, values)
	if err != nil {
		return "", err
	}

	bearerToken, err := o.selectToken(oidcResp)
	if err != nil {
		return "", err
	}

	return o.completeAuth(ctx, bearerToken)
}

// AuthenticatedClient returns a gophercloud ProviderClient authenticated
// via the OIDC Password flow.
func (o *OidcPassword) AuthenticatedClient(ctx context.Context) (*gophercloud.ProviderClient, error) {
	token, err := o.GetToken(ctx)
	if err != nil {
		return nil, err
	}
	return o.createProviderClient(ctx, token, o.GetToken)
}

// --- OidcAccessToken ---------------------------------------------------------

// OidcAccessToken authenticates by presenting an already-obtained OIDC
// access token directly to Keystone's federation endpoint.
//
// This corresponds to keystoneauth1's OidcAccessToken / v3oidcaccesstoken.
// Use this when you have an OIDC token from an external source and want
// to skip the IdP step entirely.
type OidcAccessToken struct {
	OIDCBase

	// Token is the pre-obtained OIDC access or id_token.
	Token string
}

// GetToken exchanges the pre-obtained OIDC token with Keystone.
func (o *OidcAccessToken) GetToken(ctx context.Context) (string, error) {
	if o.Token == "" {
		return "", fmt.Errorf("oidc: OidcAccessToken requires Token to be set")
	}
	return o.completeAuth(ctx, o.Token)
}

// AuthenticatedClient returns a gophercloud ProviderClient authenticated
// via a pre-obtained OIDC token.
func (o *OidcAccessToken) AuthenticatedClient(ctx context.Context) (*gophercloud.ProviderClient, error) {
	token, err := o.GetToken(ctx)
	if err != nil {
		return nil, err
	}
	return o.createProviderClient(ctx, token, o.GetToken)
}

// --- OidcAuthorizationCode ---------------------------------------------------

// OidcAuthorizationCode authenticates using the OIDC Authorization Code flow.
//
// This corresponds to keystoneauth1's OidcAuthorizationCode / v3oidcauthcode.
// In this flow the caller is responsible for completing the browser-based
// authorization redirect and obtaining the authorization code. The code is
// then exchanged here for tokens.
type OidcAuthorizationCode struct {
	OIDCBase

	// Code is the authorization code received from the IdP after the user
	// completes the browser-based authorization step.
	Code string

	// RedirectURI must match the redirect_uri registered in the IdP for this client.
	RedirectURI string
}

// GetToken exchanges the authorization code for an OIDC token, then
// exchanges that with Keystone.
func (o *OidcAuthorizationCode) GetToken(ctx context.Context) (string, error) {
	if o.Code == "" {
		return "", fmt.Errorf("oidc: OidcAuthorizationCode requires Code to be set")
	}

	tokenEndpoint, err := o.resolveTokenEndpoint(ctx)
	if err != nil {
		return "", err
	}

	values := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {o.ClientID},
		"client_secret": {o.ClientSecret},
		"code":          {o.Code},
		"redirect_uri":  {o.RedirectURI},
		"scope":         {o.scopes()},
	}

	oidcResp, err := o.postToTokenEndpoint(ctx, tokenEndpoint, values)
	if err != nil {
		return "", err
	}

	bearerToken, err := o.selectToken(oidcResp)
	if err != nil {
		return "", err
	}

	return o.completeAuth(ctx, bearerToken)
}

// AuthenticatedClient returns a gophercloud ProviderClient authenticated
// via the OIDC Authorization Code flow.
func (o *OidcAuthorizationCode) AuthenticatedClient(ctx context.Context) (*gophercloud.ProviderClient, error) {
	token, err := o.GetToken(ctx)
	if err != nil {
		return nil, err
	}
	return o.createProviderClient(ctx, token, o.GetToken)
}

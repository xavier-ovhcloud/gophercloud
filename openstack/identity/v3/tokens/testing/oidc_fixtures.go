package testing

// OIDCDiscoveryOutput is a sample OIDC discovery document response.
const OIDCDiscoveryOutput = `
{
	"issuer": "https://idp.example.com",
	"token_endpoint": "{{.TokenEndpoint}}",
	"authorization_endpoint": "{{.AuthorizationEndpoint}}",
	"jwks_uri": "{{.JWKsURI}}"
}`

// OIDCTokenOutput is a sample OIDC token endpoint response.
const OIDCTokenOutput = `
{
	"access_token": "fake-access-token",
	"id_token": "fake-id-token",
	"token_type": "Bearer",
	"expires_in": 3600
}`

// KeystoneFederationOutput is a sample Keystone federation auth response body.
const KeystoneFederationOutput = `
{
	"token": {
		"methods": ["mapped"],
		"expires_at": "2099-01-01T00:00:00.000000Z"
	}
}`

// KeystoneScopedTokenOutput is a sample Keystone scoped token response body.
const KeystoneScopedTokenOutput = `
{
	"token": {
		"methods": ["token"],
		"expires_at": "2099-01-01T00:00:00.000000Z"
	}
}`

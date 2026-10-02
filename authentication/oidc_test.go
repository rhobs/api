package authentication

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-kit/log"
	"github.com/mitchellh/mapstructure"
)

// testOIDCEnv holds a test OIDC server, signing key, and helpers for
// building signed JWT tokens that the go-oidc verifier will accept.
type testOIDCEnv struct {
	server     *httptest.Server
	issuerURL  string
	privateKey *rsa.PrivateKey
}

// newTestOIDCEnv starts an httptest server that serves OIDC discovery and JWKS
// endpoints backed by a freshly-generated RSA key pair.
func newTestOIDCEnv(t *testing.T) *testOIDCEnv {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     "test-key",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}},
	}

	env := &testOIDCEnv{privateKey: key}

	env.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 env.issuerURL,
				"jwks_uri":               env.issuerURL + "/keys",
				"authorization_endpoint": env.issuerURL + "/auth",
				"token_endpoint":         env.issuerURL + "/token",
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	env.issuerURL = env.server.URL

	return env
}

// newAuthenticator creates an oidcAuthenticator wired to the test OIDC server
// with the given username/group claim configuration.
// Each claim parameter accepts a single string (backward compat) which is
// converted to a one-element StringOrSlice, or an empty string which stays
// as a nil/empty slice.
func (env *testOIDCEnv) newAuthenticator(t *testing.T, usernameClaim, groupClaim string) *oidcAuthenticator {
	t.Helper()

	var uc, gc StringOrSlice
	if usernameClaim != "" {
		uc = StringOrSlice{usernameClaim}
	}

	if groupClaim != "" {
		gc = StringOrSlice{groupClaim}
	}

	return env.newAuthenticatorFromSlices(t, uc, gc)
}

// newAuthenticatorFromSlices creates an oidcAuthenticator with full
// StringOrSlice claim lists (for testing ordered claim list behavior).
func (env *testOIDCEnv) newAuthenticatorFromSlices(t *testing.T, usernameClaim, groupClaim StringOrSlice) *oidcAuthenticator {
	t.Helper()

	ctx := oidc.ClientContext(context.Background(), env.server.Client())

	provider, err := oidc.NewProvider(ctx, env.issuerURL)
	if err != nil {
		t.Fatalf("create OIDC provider: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:          "test-client",
		SkipClientIDCheck: true,
	})

	return &oidcAuthenticator{
		tenant: "test-tenant",
		logger: log.NewNopLogger(),
		config: oidcConfig{
			ClientID:      "test-client",
			IssuerURL:     env.issuerURL,
			UsernameClaim: usernameClaim,
			GroupClaim:    groupClaim,
		},
		provider: provider,
		verifier: verifier,
		client:   env.server.Client(),
	}
}

// signToken creates a signed JWT containing the supplied claims plus
// sensible defaults for the standard OIDC fields (iss, sub, aud, exp, iat).
func (env *testOIDCEnv) signToken(t *testing.T, extraClaims map[string]interface{}) string {
	t.Helper()

	claims := map[string]interface{}{
		"iss": env.issuerURL,
		"sub": "test-subject",
		"aud": "test-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	for k, v := range extraClaims {
		claims[k] = v
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       jose.JSONWebKey{Key: env.privateKey, KeyID: "test-key"},
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}

	return token
}

func TestCheckAuth(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.server.Close()

	tests := []struct {
		name          string
		usernameClaim string
		groupClaim    string
		extraClaims   map[string]interface{}
		wantCode      int
		wantSubject   string
		wantGroups    []string
	}{
		{
			name:          "both username and group claims present",
			usernameClaim: "preferred_username",
			groupClaim:    "groups",
			extraClaims: map[string]interface{}{
				"preferred_username": "testuser",
				"groups":             []interface{}{"group1", "group2"},
			},
			wantCode:    http.StatusOK,
			wantSubject: "testuser",
			wantGroups:  []string{"group1", "group2"},
		},
		{
			name:          "username present group claim missing proceeds with username",
			usernameClaim: "preferred_username",
			groupClaim:    "groups",
			extraClaims: map[string]interface{}{
				"preferred_username": "testuser",
				// groups claim intentionally absent
			},
			wantCode:    http.StatusOK,
			wantSubject: "testuser",
		},
		{
			name:          "group present username claim missing proceeds with group",
			usernameClaim: "preferred_username",
			groupClaim:    "groups",
			extraClaims: map[string]interface{}{
				// username claim intentionally absent
				"groups": []interface{}{"operators"},
			},
			wantCode:    http.StatusOK,
			wantSubject: "test-subject", // falls back to token subject
			wantGroups:  []string{"operators"},
		},
		{
			name:          "neither claim present returns 400",
			usernameClaim: "preferred_username",
			groupClaim:    "groups",
			extraClaims:   map[string]interface{}{},
			wantCode:      http.StatusBadRequest,
		},
		{
			name:          "username claim configured but empty string value returns 400",
			usernameClaim: "preferred_username",
			groupClaim:    "groups",
			extraClaims: map[string]interface{}{
				"preferred_username": "",
				"groups":             []interface{}{"group1"},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name:          "username claim configured wrong type returns 400",
			usernameClaim: "preferred_username",
			groupClaim:    "groups",
			extraClaims: map[string]interface{}{
				"preferred_username": 12345,
				"groups":             []interface{}{"group1"},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name:          "group claim as string extracts single group",
			usernameClaim: "preferred_username",
			groupClaim:    "groups",
			extraClaims: map[string]interface{}{
				"preferred_username": "testuser",
				"groups":             "single-group",
			},
			wantCode:    http.StatusOK,
			wantSubject: "testuser",
			wantGroups:  []string{"single-group"},
		},
		{
			name:          "group claim as slice of strings extracts multiple groups",
			usernameClaim: "preferred_username",
			groupClaim:    "groups",
			extraClaims: map[string]interface{}{
				"preferred_username": "testuser",
				"groups":             []interface{}{"alpha", "beta", "gamma"},
			},
			wantCode:    http.StatusOK,
			wantSubject: "testuser",
			wantGroups:  []string{"alpha", "beta", "gamma"},
		},
		{
			name:          "no username or group claims configured uses token subject",
			usernameClaim: "",
			groupClaim:    "",
			extraClaims:   map[string]interface{}{},
			wantCode:      http.StatusOK,
			wantSubject:   "test-subject",
		},
		{
			name:          "group claim with non-string elements converted via Sprintf",
			usernameClaim: "preferred_username",
			groupClaim:    "groups",
			extraClaims: map[string]interface{}{
				"preferred_username": "testuser",
				"groups":             []interface{}{42, true},
			},
			wantCode:    http.StatusOK,
			wantSubject: "testuser",
			wantGroups:  []string{"42", "true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := env.newAuthenticator(t, tt.usernameClaim, tt.groupClaim)
			token := env.signToken(t, tt.extraClaims)

			ctx, _, httpCode, _ := auth.checkAuth(context.Background(), token)

			if httpCode != tt.wantCode {
				t.Fatalf("HTTP status = %d, want %d", httpCode, tt.wantCode)
			}

			if tt.wantCode != http.StatusOK {
				return
			}

			if tt.wantSubject != "" {
				gotSubject, ok := GetSubject(ctx)
				if !ok {
					t.Fatal("expected subject in context, got none")
				}

				if gotSubject != tt.wantSubject {
					t.Errorf("subject = %q, want %q", gotSubject, tt.wantSubject)
				}
			}

			if tt.wantGroups != nil {
				gotGroups, ok := GetGroups(ctx)
				if !ok {
					t.Fatal("expected groups in context, got none")
				}

				if len(gotGroups) != len(tt.wantGroups) {
					t.Fatalf("got %d groups %v, want %d groups %v",
						len(gotGroups), gotGroups, len(tt.wantGroups), tt.wantGroups)
				}

				for i, g := range gotGroups {
					if g != tt.wantGroups[i] {
						t.Errorf("groups[%d] = %q, want %q", i, g, tt.wantGroups[i])
					}
				}
			}
		})
	}
}

func TestCheckAuthClaimLists(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.server.Close()

	tests := []struct {
		name          string
		usernameClaim StringOrSlice
		groupClaim    StringOrSlice
		extraClaims   map[string]interface{}
		wantCode      int
		wantSubject   string
		wantGroups    []string
	}{
		{
			name:          "username list first claim matches",
			usernameClaim: StringOrSlice{"preferred_username", "email"},
			groupClaim:    StringOrSlice{"groups"},
			extraClaims: map[string]interface{}{
				"preferred_username": "alice",
				"email":              "alice@example.com",
				"groups":             []interface{}{"devs"},
			},
			wantCode:    http.StatusOK,
			wantSubject: "alice",
			wantGroups:  []string{"devs"},
		},
		{
			name:          "username list second claim matches when first absent",
			usernameClaim: StringOrSlice{"preferred_username", "email"},
			groupClaim:    StringOrSlice{"groups"},
			extraClaims: map[string]interface{}{
				// preferred_username absent
				"email":  "bob@example.com",
				"groups": []interface{}{"ops"},
			},
			wantCode:    http.StatusOK,
			wantSubject: "bob@example.com",
			wantGroups:  []string{"ops"},
		},
		{
			name:          "group list first claim matches",
			usernameClaim: StringOrSlice{"preferred_username"},
			groupClaim:    StringOrSlice{"org_id", "rh-org-id", "groups"},
			extraClaims: map[string]interface{}{
				"preferred_username": "carol",
				"org_id":             "org-123",
				"groups":             []interface{}{"team-a"},
			},
			wantCode:    http.StatusOK,
			wantSubject: "carol",
			wantGroups:  []string{"org-123"},
		},
		{
			name:          "group list second claim matches when first absent",
			usernameClaim: StringOrSlice{"preferred_username"},
			groupClaim:    StringOrSlice{"org_id", "rh-org-id", "groups"},
			extraClaims: map[string]interface{}{
				"preferred_username": "dave",
				// org_id absent
				"rh-org-id": "rh-456",
				"groups":    []interface{}{"team-b"},
			},
			wantCode:    http.StatusOK,
			wantSubject: "dave",
			wantGroups:  []string{"rh-456"},
		},
		{
			name:          "no claims match across both lists returns 400",
			usernameClaim: StringOrSlice{"preferred_username", "email"},
			groupClaim:    StringOrSlice{"org_id", "rh-org-id"},
			extraClaims:   map[string]interface{}{
				// none of the configured claims are present
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name:          "mixed lists only group matches proceeds OK",
			usernameClaim: StringOrSlice{"preferred_username", "email"},
			groupClaim:    StringOrSlice{"org_id", "groups"},
			extraClaims: map[string]interface{}{
				// no username claims present
				"groups": []interface{}{"sre-team"},
			},
			wantCode:    http.StatusOK,
			wantSubject: "test-subject", // falls back to token subject
			wantGroups:  []string{"sre-team"},
		},
		{
			name:          "mixed lists only username matches proceeds OK",
			usernameClaim: StringOrSlice{"email"},
			groupClaim:    StringOrSlice{"org_id", "rh-org-id"},
			extraClaims: map[string]interface{}{
				"email": "eve@example.com",
				// no group claims present
			},
			wantCode:    http.StatusOK,
			wantSubject: "eve@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := env.newAuthenticatorFromSlices(t, tt.usernameClaim, tt.groupClaim)
			token := env.signToken(t, tt.extraClaims)

			ctx, _, httpCode, _ := auth.checkAuth(context.Background(), token)

			if httpCode != tt.wantCode {
				t.Fatalf("HTTP status = %d, want %d", httpCode, tt.wantCode)
			}

			if tt.wantCode != http.StatusOK {
				return
			}

			if tt.wantSubject != "" {
				gotSubject, ok := GetSubject(ctx)
				if !ok {
					t.Fatal("expected subject in context, got none")
				}

				if gotSubject != tt.wantSubject {
					t.Errorf("subject = %q, want %q", gotSubject, tt.wantSubject)
				}
			}

			if tt.wantGroups != nil {
				gotGroups, ok := GetGroups(ctx)
				if !ok {
					t.Fatal("expected groups in context, got none")
				}

				if len(gotGroups) != len(tt.wantGroups) {
					t.Fatalf("got %d groups %v, want %d groups %v",
						len(gotGroups), gotGroups, len(tt.wantGroups), tt.wantGroups)
				}

				for i, g := range gotGroups {
					if g != tt.wantGroups[i] {
						t.Errorf("groups[%d] = %q, want %q", i, g, tt.wantGroups[i])
					}
				}
			}
		})
	}
}

// newAuthenticatorViaMapstructure creates an oidcAuthenticator by running
// the raw config map through mapstructure.Decode with stringOrSliceDecodeHook,
// exactly as the production code path does.  This exercises the decode hook
// for StringOrSlice fields (UsernameClaim, GroupClaim) where values may arrive
// as plain strings — including JSON-encoded arrays that config generators
// sometimes produce.
func (env *testOIDCEnv) newAuthenticatorViaMapstructure(t *testing.T, rawConfig map[string]interface{}) *oidcAuthenticator {
	t.Helper()

	var config oidcConfig

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: stringOrSliceDecodeHook(),
		Result:     &config,
	})
	if err != nil {
		t.Fatalf("create mapstructure decoder: %v", err)
	}

	if err := decoder.Decode(rawConfig); err != nil {
		t.Fatalf("mapstructure decode: %v", err)
	}

	ctx := oidc.ClientContext(context.Background(), env.server.Client())

	provider, err := oidc.NewProvider(ctx, env.issuerURL)
	if err != nil {
		t.Fatalf("create OIDC provider: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:          "test-client",
		SkipClientIDCheck: true,
	})

	return &oidcAuthenticator{
		tenant: "test-tenant",
		logger: log.NewNopLogger(),
		config: config,
		provider: provider,
		verifier: verifier,
		client:   env.server.Client(),
	}
}

func TestCheckAuthMapstructureJSONArrayString(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.server.Close()

	tests := []struct {
		name        string
		rawConfig   map[string]interface{}
		extraClaims map[string]interface{}
		wantCode    int
		wantSubject string
		wantGroups  []string
	}{
		{
			name: "groupClaim JSON array string JWT has second claim",
			rawConfig: map[string]interface{}{
				"clientID":      "test-client",
				"issuerURL":     "PLACEHOLDER",
				"usernameClaim": "preferred_username",
				"groupClaim":    `["org_id", "rh-org-id"]`,
			},
			extraClaims: map[string]interface{}{
				"preferred_username": "testuser",
				"rh-org-id":          "12541229",
			},
			wantCode:    http.StatusOK,
			wantSubject: "testuser",
			wantGroups:  []string{"12541229"},
		},
		{
			name: "groupClaim JSON array string JWT has first claim",
			rawConfig: map[string]interface{}{
				"clientID":      "test-client",
				"issuerURL":     "PLACEHOLDER",
				"usernameClaim": "preferred_username",
				"groupClaim":    `["org_id", "rh-org-id"]`,
			},
			extraClaims: map[string]interface{}{
				"preferred_username": "testuser",
				"org_id":             "6340056",
			},
			wantCode:    http.StatusOK,
			wantSubject: "testuser",
			wantGroups:  []string{"6340056"},
		},
		{
			name: "usernameClaim JSON array string JWT has fallback claim",
			rawConfig: map[string]interface{}{
				"clientID":      "test-client",
				"issuerURL":     "PLACEHOLDER",
				"usernameClaim": `["email", "preferred_username"]`,
				"groupClaim":    "groups",
			},
			extraClaims: map[string]interface{}{
				"preferred_username": "user@example.com",
				"groups":             []interface{}{"team-a"},
			},
			wantCode:    http.StatusOK,
			wantSubject: "user@example.com",
			wantGroups:  []string{"team-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.rawConfig["issuerURL"] = env.issuerURL

			auth := env.newAuthenticatorViaMapstructure(t, tt.rawConfig)
			token := env.signToken(t, tt.extraClaims)

			ctx, _, httpCode, _ := auth.checkAuth(context.Background(), token)

			if httpCode != tt.wantCode {
				t.Fatalf("HTTP status = %d, want %d", httpCode, tt.wantCode)
			}

			if tt.wantCode != http.StatusOK {
				return
			}

			if tt.wantSubject != "" {
				gotSubject, ok := GetSubject(ctx)
				if !ok {
					t.Fatal("expected subject in context, got none")
				}

				if gotSubject != tt.wantSubject {
					t.Errorf("subject = %q, want %q", gotSubject, tt.wantSubject)
				}
			}

			if tt.wantGroups != nil {
				gotGroups, ok := GetGroups(ctx)
				if !ok {
					t.Fatal("expected groups in context, got none")
				}

				if len(gotGroups) != len(tt.wantGroups) {
					t.Fatalf("got %d groups %v, want %d groups %v",
						len(gotGroups), gotGroups, len(tt.wantGroups), tt.wantGroups)
				}

				for i, g := range gotGroups {
					if g != tt.wantGroups[i] {
						t.Errorf("groups[%d] = %q, want %q", i, g, tt.wantGroups[i])
					}
				}
			}
		})
	}
}

func TestStringOrSliceDecodeHookJSONArrayString(t *testing.T) {
	hook := stringOrSliceDecodeHook()
	fn := hook.(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))

	targetType := reflect.TypeOf(StringOrSlice{})

	tests := []struct {
		name  string
		input interface{}
		want  StringOrSlice
	}{
		{
			name:  "JSON array string is parsed into slice",
			input: `["org_id", "rh-org-id"]`,
			want:  StringOrSlice{"org_id", "rh-org-id"},
		},
		{
			name:  "plain string stays as single-element slice",
			input: "preferred_username",
			want:  StringOrSlice{"preferred_username"},
		},
		{
			name:  "string that is not valid JSON array stays as single-element",
			input: "not-json",
			want:  StringOrSlice{"not-json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := fn(reflect.TypeOf(tt.input), targetType, tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got, ok := result.(StringOrSlice)
			if !ok {
				t.Fatalf("expected StringOrSlice, got %T", result)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("got %v (len %d), want %v (len %d)", got, len(got), tt.want, len(tt.want))
			}

			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("element %d = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestStringOrSliceUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    StringOrSlice
		wantErr bool
	}{
		{
			name:  "single string",
			input: `"preferred_username"`,
			want:  StringOrSlice{"preferred_username"},
		},
		{
			name:  "array of strings",
			input: `["preferred_username","email"]`,
			want:  StringOrSlice{"preferred_username", "email"},
		},
		{
			name:  "empty array",
			input: `[]`,
			want:  StringOrSlice{},
		},
		{
			name:    "invalid type number",
			input:   `42`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got StringOrSlice
			err := got.UnmarshalJSON([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}

			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("element %d = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

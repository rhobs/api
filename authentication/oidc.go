package authentication

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/efficientgo/core/backoff"
	"github.com/go-chi/chi/v5"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/observatorium/api/httperr"
)

// StringOrSlice is a []string that can be unmarshaled from either a single
// JSON string or a JSON array of strings.  When a single string is provided
// it becomes a one-element slice, preserving backward compatibility with
// configs that specify a single claim name.
type StringOrSlice []string

// UnmarshalJSON implements json.Unmarshaler.
// It accepts both `"claim"` and `["claim1","claim2"]`.
func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = StringOrSlice{str}

		return nil
	}

	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return fmt.Errorf("StringOrSlice: expected string or []string: %w", err)
	}

	*s = StringOrSlice(arr)

	return nil
}

// MarshalJSON implements json.Marshaler.
func (s StringOrSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(s))
}

// stringOrSliceDecodeHook is a mapstructure DecodeHookFunc that converts
// a string or []interface{} to StringOrSlice when the target type matches.
func stringOrSliceDecodeHook() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if t != reflect.TypeOf(StringOrSlice{}) {
			return data, nil
		}

		switch v := data.(type) {
		case string:
			// Check if the string is a JSON-encoded array (e.g. from config generators
			// that store arrays in string-typed fields).
			var arr []string
			if err := json.Unmarshal([]byte(v), &arr); err == nil {
				return StringOrSlice(arr), nil
			}

			return StringOrSlice{v}, nil
		case []interface{}:
			result := make([]string, len(v))
			for i, elem := range v {
				s, ok := elem.(string)
				if !ok {
					return nil, fmt.Errorf("StringOrSlice element %d is not a string", i)
				}

				result[i] = s
			}

			return StringOrSlice(result), nil
		case []string:
			return v, nil
		default:
			return data, nil
		}
	}
}

// OIDCAuthenticatorType represents the oidc authentication provider type.
const OIDCAuthenticatorType = "oidc"

func init() {
	onboardNewProvider(OIDCAuthenticatorType, newOIDCAuthenticator)
}

// oidcConfig represents the oidc authenticator config.
type oidcConfig struct {
	ClientID      string        `json:"clientID"`
	ClientSecret  string        `json:"clientSecret"`
	GroupClaim    StringOrSlice `json:"groupClaim"`
	IssuerRawCA   []byte        `json:"issuerCA"`
	IssuerCAPath  string        `json:"issuerCAPath"`
	issuerCA      *x509.Certificate
	IssuerURL     string        `json:"issuerURL"`
	RedirectURL   string        `json:"redirectURL"`
	UsernameClaim StringOrSlice `json:"usernameClaim"`
}

type oidcAuthenticator struct {
	tenant       string
	logger       log.Logger
	config       oidcConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	client       *http.Client
	cookieName   string
	redirectURL  string
	oauth2Config oauth2.Config
	handler      http.Handler
}

func newOIDCAuthenticator(c map[string]interface{}, tenant string,
	registrationRetryCount *prometheus.CounterVec, logger log.Logger,
) (Provider, error) {
	var config oidcConfig

	const (
		loginRoute    = "/login"
		callbackRoute = "/callback"
		handlerPrefix = "/oidc/{tenant}"
	)

	ctx := context.Background()

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: stringOrSliceDecodeHook(),
		Result:     &config,
	})
	if err != nil {
		return nil, fmt.Errorf("create config decoder: %w", err)
	}

	if err := decoder.Decode(c); err != nil {
		return nil, err
	}

	if len(config.IssuerURL) == 0 {
		return nil, fmt.Errorf("issuerURL is required")
	}

	if config.IssuerCAPath != "" {
		IssuerRawCA, err := os.ReadFile(config.IssuerCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read issuer ca file: %s", err.Error())
		}

		config.IssuerRawCA = IssuerRawCA
	}

	if len(config.IssuerRawCA) != 0 {
		block, _ := pem.Decode(config.IssuerRawCA)
		if block == nil {
			return nil, fmt.Errorf("failed to parse issuer CA certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse issuer certificate: %s", err.Error())
		}

		config.issuerCA = cert
	}

	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if config.issuerCA != nil {
		t.TLSClientConfig = &tls.Config{
			RootCAs: x509.NewCertPool(),
		}
		t.TLSClientConfig.RootCAs.AddCert(config.issuerCA)
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: t,
	}

	provider := newOIDCProvider(oidc.ClientContext(ctx, client), tenant, client, config.IssuerURL, registrationRetryCount, logger)

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{"openid", "profile", "email", "groups"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID, SkipClientIDCheck: true})

	oidcProvider := &oidcAuthenticator{
		tenant:       tenant,
		logger:       logger,
		config:       config,
		oauth2Config: oauth2Config,
		provider:     provider,
		verifier:     verifier,
		client:       client,
		cookieName:   fmt.Sprintf("observatorium_%s", tenant),
		redirectURL:  path.Join("/", tenant),
	}

	r := chi.NewRouter()
	r.Handle(loginRoute, oidcProvider.oidcLoginHandler(&oauth2Config))
	r.Handle(callbackRoute, oidcProvider.oidcCallBackHandler())
	oidcProvider.handler = r

	return oidcProvider, nil
}

func newOIDCProvider(ctx context.Context, tenant string, client *http.Client, issuerURL string,
	registrationRetryCount *prometheus.CounterVec, logger log.Logger,
) *oidc.Provider {
	var provider *oidc.Provider

	var err error

	b := backoff.New(ctx, backoff.Config{
		Min:        500 * time.Millisecond,
		Max:        5 * time.Second,
		MaxRetries: 0, // Retry indefinitely.
	})

	for b.Reset(); b.Ongoing(); {
		provider, err = oidc.NewProvider(oidc.ClientContext(ctx, client), issuerURL)
		if err != nil {
			level.Error(logger).Log(
				"tenant", tenant,
				"msg", fmt.Sprintf("failed to initialize authenticator %s after %d retries: %s",
					OIDCAuthenticatorType, b.NumRetries(), err))
			registrationRetryCount.WithLabelValues(tenant, OIDCAuthenticatorType).Inc()
			b.Wait()

			continue
		}

		break
	}

	return provider
}

func (a oidcAuthenticator) oidcLoginHandler(oauth2Config *oauth2.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := oauth2Config.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusSeeOther)
	})
}

func (a oidcAuthenticator) oidcCallBackHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.ClientContext(r.Context(), a.client)

		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			msg := fmt.Sprintf("%s: %s", errMsg, desc)
			level.Debug(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusBadRequest)
			return
		}

		queryCode := r.URL.Query().Get("code")
		if queryCode == "" {
			const msg = "no code in request"
			level.Debug(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusBadRequest)
			return
		}
		queryState := r.URL.Query().Get("state")
		if queryState != state {
			const msg = "incorrect state in request"
			level.Debug(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusBadRequest)
			return
		}

		token, err := a.oauth2Config.Exchange(ctx, queryCode)
		if err != nil {
			msg := fmt.Sprintf("failed to get token: %v", err)
			level.Warn(a.logger).Log("msg", msg, "err", err)
			httperr.PrometheusAPIError(w, msg, http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			const msg = "no id_token in token response"
			level.Warn(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusInternalServerError)
			return
		}

		_, err = a.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			msg := fmt.Sprintf("failed to verify ID token: %v", err)
			level.Warn(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    a.cookieName,
			Value:   rawIDToken,
			Path:    "/",
			Expires: token.Expiry,
		})

		http.Redirect(w, r, a.redirectURL, http.StatusFound)
	})
}

func (a oidcAuthenticator) Handler() (string, http.Handler) {
	return "/oidc/{tenant}", a.handler
}

//nolint:gocognit
func (a oidcAuthenticator) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string

			authorizationHeader := r.Header.Get("Authorization")
			if authorizationHeader != "" {
				authorization := strings.Split(authorizationHeader, " ")
				if len(authorization) != 2 {
					const msg = "invalid Authorization header"
					level.Debug(a.logger).Log("msg", msg)
					httperr.PrometheusAPIError(w, msg, http.StatusUnauthorized)
					return
				}

				token = authorization[1]
			} else {
				cookie, err := r.Cookie(a.cookieName)
				if err != nil {
					tenant, ok := GetTenant(r.Context())
					if !ok {
						const msg = "error finding tenant"
						level.Warn(a.logger).Log("msg", msg)
						httperr.PrometheusAPIError(w, msg, http.StatusInternalServerError)
						return
					}
					// Redirect users to the OIDC login
					w.Header().Set("Location", path.Join("/oidc", tenant, "/login"))
					httperr.PrometheusAPIError(w, "failed to find token", http.StatusFound)
					return
				}
				token = cookie.Value
			}

			ctx, msg, code, _ := a.checkAuth(r.Context(), token)
			if code != http.StatusOK {
				httperr.PrometheusAPIError(w, msg, code)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

//nolint:gocognit
func (a oidcAuthenticator) GRPCMiddleware() grpc.StreamServerInterceptor {
	return grpc_middleware_auth.StreamServerInterceptor(func(ctx context.Context) (context.Context, error) {
		var token string

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return ctx, status.Error(codes.Internal, "metadata error")
		}

		authorizationHeaders := md.Get("Authorization")
		if len(authorizationHeaders) > 0 {
			if authorizationHeaders[0] != "" {
				authorization := strings.Split(authorizationHeaders[0], " ")
				if len(authorization) != 2 {
					return ctx, status.Error(codes.InvalidArgument, "invalid Authorization header")
				}

				token = authorization[1]
			}
		}

		ctx, msg, _, code := a.checkAuth(ctx, token)
		if code != codes.OK {
			return ctx, status.Error(code, msg)
		}

		return ctx, nil
	})
}

func (a oidcAuthenticator) checkAuth(ctx context.Context, token string) (context.Context, string, int, codes.Code) {
	idToken, err := a.verifier.Verify(oidc.ClientContext(ctx, a.client), token)
	if err != nil {
		const msg = "failed to verify ID token"

		// Verification failure can be anything from an OIDC connection problem, bogus bearer token,
		// or expired token.  The HTTP version surfaced this to the user, which we don't want to do.
		// We log it to allow the possibility of debugging this.
		level.Debug(a.logger).Log("msg", msg, "err", err)

		var tokenExpiredErr *oidc.TokenExpiredError
		if errors.As(err, &tokenExpiredErr) {
			return ctx, "token is expired", http.StatusForbidden, codes.Unauthenticated
		}

		// The original HTTP implementation returned StatusInternalServerError.
		// For gRPC we return Unknown, as we can't really
		// be sure the problem is internal and not deserving Unauthenticated or InvalidArgument.
		return ctx, msg, http.StatusInternalServerError, codes.Unknown
	}

	sub := idToken.Subject
	usernameExtracted := false
	hasUsernameClaims := len(a.config.UsernameClaim) > 0
	hasGroupClaims := len(a.config.GroupClaim) > 0

	// Extract claims once for both username and group lookups.
	var claims map[string]interface{}

	if hasUsernameClaims || hasGroupClaims {
		claims = map[string]interface{}{}
		if err := idToken.Claims(&claims); err != nil {
			const msg = "failed to read claims"

			level.Warn(a.logger).Log("msg", msg, "err", err)

			return ctx, msg, http.StatusInternalServerError, codes.Internal
		}
	}

	// Try username claims in order of preference — first match wins.
	if hasUsernameClaims {
		for _, claimName := range a.config.UsernameClaim {
			rawUsername, ok := claims[claimName]
			if !ok {
				continue
			}

			username, ok := rawUsername.(string)
			if !ok || username == "" {
				const msg = "invalid username claim value"

				level.Debug(a.logger).Log("msg", msg, "claim", claimName)

				return ctx, msg, http.StatusBadRequest, codes.PermissionDenied
			}

			sub = username
			usernameExtracted = true

			break
		}

		if !usernameExtracted && !hasGroupClaims {
			const msg = "username cannot be empty"

			level.Debug(a.logger).Log("msg", msg)

			return ctx, msg, http.StatusBadRequest, codes.PermissionDenied
		}

		if !usernameExtracted {
			level.Debug(a.logger).Log("msg", "username claim not found in token, proceeding with group claim")
		}
	}

	ctx = context.WithValue(ctx, subjectKey, sub)

	// Try group claims in order of preference — first match wins.
	groupExtracted := false

	if hasGroupClaims {
		for _, claimName := range a.config.GroupClaim {
			rawGroup, ok := claims[claimName]
			if !ok {
				continue
			}

			var groups []string

			switch v := rawGroup.(type) {
			case string:
				groups = append(groups, v)
			case []string:
				groups = v
			case []interface{}:
				groups = make([]string, 0, len(v))
				for i := range v {
					groups = append(groups, fmt.Sprintf("%v", v[i]))
				}
			}

			ctx = context.WithValue(ctx, groupsKey, groups)
			groupExtracted = true

			break
		}

		if !groupExtracted {
			if usernameExtracted {
				level.Debug(a.logger).Log("msg", "group claim not found, proceeding with username")
			} else {
				const msg = "group cannot be empty"

				level.Debug(a.logger).Log("msg", msg)

				return ctx, msg, http.StatusBadRequest, codes.PermissionDenied
			}
		}
	}

	// Safety gate: when both claim lists are configured, at least one must match.
	if hasUsernameClaims && hasGroupClaims && !usernameExtracted && !groupExtracted {
		const msg = "no matching claims found"

		level.Debug(a.logger).Log("msg", msg)

		return ctx, msg, http.StatusBadRequest, codes.PermissionDenied
	}

	return ctx, "", http.StatusOK, codes.OK
}

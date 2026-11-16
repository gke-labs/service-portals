// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedauthv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/klog/v2"
)

const (
	extraNodeName   = "authentication.kubernetes.io/node-name"
	defaultCacheTTL = 5 * time.Minute
)

// Caller represents the authenticated identity of an incoming caller.
type Caller struct {
	ServiceAccount string
	NodeName       string
	ExpiresAt      time.Time
}

// AuthenticatorConfig configures an Authenticator.
type AuthenticatorConfig struct {
	// Audience is the required TokenReview audience for the controller.
	Audience string

	// NodeAgentAccount is the service account allowed for node agents.
	NodeAgentAccount string

	// ClientAllowlist is the list of permitted client service accounts.
	ClientAllowlist []string

	// TokenReviews is the Kubernetes TokenReviews client interface.
	TokenReviews typedauthv1.TokenReviewInterface

	// CacheTTL optionally overrides the default cache duration.
	CacheTTL time.Duration
}

type cacheEntry struct {
	caller    *Caller
	expiresAt time.Time
}

// Authenticator identifies and authorizes incoming gRPC callers using Kubernetes TokenReview.
type Authenticator struct {
	audience         string
	nodeAgentAccount string
	clientAllowlist  map[string]bool
	tokenReviews     typedauthv1.TokenReviewInterface
	cacheTTL         time.Duration
	now              func() time.Time

	mu    sync.RWMutex
	cache map[[32]byte]cacheEntry
}

// NewAuthenticator constructs an Authenticator with the given configuration.
func NewAuthenticator(cfg AuthenticatorConfig) (*Authenticator, error) {
	if cfg.Audience == "" {
		return nil, errors.New("controller audience is required")
	}
	if cfg.TokenReviews == nil {
		return nil, errors.New("TokenReviews client is required")
	}

	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}

	allowlist := make(map[string]bool, len(cfg.ClientAllowlist))
	for _, sa := range cfg.ClientAllowlist {
		allowlist[sa] = true
	}

	return &Authenticator{
		audience:         cfg.Audience,
		nodeAgentAccount: cfg.NodeAgentAccount,
		clientAllowlist:  allowlist,
		tokenReviews:     cfg.TokenReviews,
		cacheTTL:         ttl,
		now:              time.Now,
		cache:            make(map[[32]byte]cacheEntry),
	}, nil
}

// Authenticate extracts and authenticates the caller's service account token from the gRPC context.
func (a *Authenticator) Authenticate(ctx context.Context) (*Caller, error) {
	token, err := extractToken(ctx)
	if err != nil {
		a.logRefusal(ctx, "", "missing or invalid token")
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	tokenHash := sha256.Sum256([]byte(token))

	a.mu.RLock()
	entry, ok := a.cache[tokenHash]
	a.mu.RUnlock()
	if ok && a.now().Before(entry.expiresAt) {
		return entry.caller, nil
	}

	tr := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{a.audience},
		},
	}

	res, err := a.tokenReviews.Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		a.logRefusal(ctx, "", "token review request failed: "+err.Error())
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if res == nil {
		a.logRefusal(ctx, "", "empty token review response")
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	if res.Status.Error != "" {
		a.logRefusal(ctx, res.Status.User.Username, "token review error: "+res.Status.Error)
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if !res.Status.Authenticated {
		a.logRefusal(ctx, res.Status.User.Username, "token is not authenticated")
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	var audienceMatched bool
	for _, aud := range res.Status.Audiences {
		if aud == a.audience {
			audienceMatched = true
			break
		}
	}
	if !audienceMatched {
		a.logRefusal(ctx, res.Status.User.Username, "token audience mismatch")
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	// The caller's identity expires when the token itself does, falling back
	// to the cache duration if the token's expiry cannot be read.
	identityExp := a.now().Add(a.cacheTTL)
	tokenExp, hasExp := parseTokenExpiry(token)
	if hasExp {
		identityExp = tokenExp
	}

	// Results may be cached briefly so long-lived streams are not re-reviewed
	// on every message, but a cached identity must expire no later than the token does.
	cacheExpiresAt := a.now().Add(a.cacheTTL)
	if hasExp && tokenExp.Before(cacheExpiresAt) {
		cacheExpiresAt = tokenExp
	}

	caller := &Caller{
		ServiceAccount: res.Status.User.Username,
		ExpiresAt:      identityExp,
	}
	if res.Status.User.Extra != nil {
		if vals := res.Status.User.Extra[extraNodeName]; len(vals) > 0 {
			caller.NodeName = vals[0]
		}
	}

	if a.now().Before(cacheExpiresAt) {
		a.mu.Lock()
		if len(a.cache) > 1000 {
			now := a.now()
			for k, v := range a.cache {
				if now.After(v.expiresAt) {
					delete(a.cache, k)
				}
			}
		}
		a.cache[tokenHash] = cacheEntry{
			caller:    caller,
			expiresAt: cacheExpiresAt,
		}
		a.mu.Unlock()
	}

	return caller, nil
}

// AuthorizeNodeAgent authenticates the caller and verifies that it is the configured node agent.
//
// The Kubernetes documentation notes that node information in a bound token
// (authentication.kubernetes.io/node-name) is not verified by the API server
// when the token is used (see https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/).
//
// However, the node name is trustworthy here because only the API server can mint
// service account tokens, and it only mints bound tokens when asked by:
//  1. The kubelet for pods running on its own node (via projected volume mounts).
//  2. Callers with the RBAC permission to create tokens ("create" on the
//     "serviceaccounts/token" resource) for that service account, who could request
//     a token bound to a node agent pod on any node and be routed that node's pushes.
//
// Therefore, the controller treats the node claim as identifying the node agent's node
// only in combination with the service account check, and cluster operators must
// strictly guard "create" permission on "serviceaccounts/token" for the node agent's
// service account.
//
// Returns the verified node name and the identity's expiration time so long-lived
// streams can be terminated when their credential expires.
func (a *Authenticator) AuthorizeNodeAgent(ctx context.Context) (string, time.Time, error) {
	caller, err := a.Authenticate(ctx)
	if err != nil {
		return "", time.Time{}, err
	}

	if a.nodeAgentAccount == "" || caller.ServiceAccount != a.nodeAgentAccount {
		a.logRefusal(ctx, caller.ServiceAccount, "caller is not authorized as node agent")
		return "", time.Time{}, status.Errorf(codes.PermissionDenied, "caller %q is not authorized as node agent", caller.ServiceAccount)
	}

	if caller.NodeName == "" {
		a.logRefusal(ctx, caller.ServiceAccount, "node agent token is not bound to a node")
		return "", time.Time{}, status.Errorf(codes.PermissionDenied, "caller %q token is not bound to a node", caller.ServiceAccount)
	}

	return caller.NodeName, caller.ExpiresAt, nil
}

// AuthorizeClient authenticates the caller and verifies that it is on the client allowlist.
func (a *Authenticator) AuthorizeClient(ctx context.Context) (string, error) {
	caller, err := a.Authenticate(ctx)
	if err != nil {
		return "", err
	}

	if len(a.clientAllowlist) == 0 {
		a.logRefusal(ctx, caller.ServiceAccount, "client allowlist is empty")
		return "", status.Errorf(codes.PermissionDenied, "client allowlist is empty")
	}

	if !a.clientAllowlist[caller.ServiceAccount] {
		a.logRefusal(ctx, caller.ServiceAccount, "caller is not on client allowlist")
		return "", status.Errorf(codes.PermissionDenied, "caller %q is not on allowlist", caller.ServiceAccount)
	}

	return caller.ServiceAccount, nil
}

func (a *Authenticator) logRefusal(ctx context.Context, sa, reason string) {
	method := methodFromContext(ctx)
	if sa != "" {
		klog.Infof("refused %s for %s: %s", method, sa, reason)
	} else {
		klog.Infof("refused %s: %s", method, reason)
	}
}

func methodFromContext(ctx context.Context) string {
	if m, ok := grpc.Method(ctx); ok && m != "" {
		return m
	}
	return "unknown"
}

func extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("missing metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", errors.New("missing authorization header")
	}
	raw := strings.TrimSpace(vals[0])
	if raw == "" {
		return "", errors.New("empty authorization header")
	}

	token := raw
	if strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		token = strings.TrimSpace(raw[7:])
	}
	if token == "" {
		return "", errors.New("empty bearer token")
	}
	return token, nil
}

func parseTokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(data, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

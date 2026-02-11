package proxy

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

const anthropicHost = "api.anthropic.com"

// AuthProxy is a reverse proxy that injects an API key header before
// forwarding requests to api.anthropic.com. It runs on the host so that
// containers never need the token at all.
type AuthProxy struct {
	server *http.Server
	token  string
	secret string // shared secret containers must present to use the proxy
	addr   string
}

// New creates an AuthProxy that will listen on the given port and inject
// the provided token as an x-api-key header on every forwarded request.
// If secret is non-empty, incoming requests must present it as the x-api-key
// header value (this is what Claude Code sends when ANTHROPIC_API_KEY is set
// to the proxy secret inside the container).
func New(port int, token, secret string) *AuthProxy {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ap := &AuthProxy{
		token:  token,
		secret: secret,
		addr:   addr,
	}

	target := &url.URL{Scheme: "https", Host: anthropicHost}
	rp := httputil.NewSingleHostReverseProxy(target)

	// Customise the Director to set auth headers.
	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		origDirector(r)
		// Strip any auth headers the caller may have sent.
		r.Header.Del("x-api-key")
		r.Header.Del("Authorization")
		// Inject the real token.
		r.Header.Set("x-api-key", ap.token)
		r.Host = anthropicHost
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ap.handleProxy(rp))

	ap.server = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return ap
}

// handleProxy validates the shared secret before forwarding to the reverse proxy.
func (ap *AuthProxy) handleProxy(rp *httputil.ReverseProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ap.secret != "" {
			presented := r.Header.Get("x-api-key")
			if subtle.ConstantTimeCompare([]byte(presented), []byte(ap.secret)) != 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		rp.ServeHTTP(w, r)
	}
}

// Start begins listening. It returns an error if the bind fails.
// The server runs in a background goroutine.
func (ap *AuthProxy) Start() error {
	ln, err := net.Listen("tcp", ap.addr)
	if err != nil {
		return fmt.Errorf("auth proxy listen: %w", err)
	}
	go func() {
		_ = ap.server.Serve(ln) // returns on Close/Shutdown
	}()
	return nil
}

// Close gracefully shuts down the proxy.
func (ap *AuthProxy) Close(ctx context.Context) error {
	return ap.server.Shutdown(ctx)
}

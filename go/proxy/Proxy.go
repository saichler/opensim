/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package proxy

import (
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/saichler/l8types/go/ifs"
)

// WebProxy handles proxying requests to a backend simulator HTTP server
type WebProxy struct {
	simulatorURL *url.URL
	proxy        *httputil.ReverseProxy
	validator    ifs.BearerValidator
}

// NewWebProxy creates a new WebProxy instance
// simulatorHost: the IP/hostname and port of the simulator (e.g., "192.168.1.100:8080")
func NewWebProxy(simulatorHost string) (*WebProxy, error) {
	targetURL, err := url.Parse("http://" + simulatorHost)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Configure the proxy director to modify requests before forwarding
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
	}

	// Configure error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Proxy error: "+err.Error(), http.StatusBadGateway)
	}

	return &WebProxy{
		simulatorURL: targetURL,
		proxy:        proxy,
	}, nil
}

// SetValidator sets the bearer token validator
func (wp *WebProxy) SetValidator(validator ifs.BearerValidator) {
	wp.validator = validator
}

// validateAndProxy validates the bearer token and forwards the request if valid
func (wp *WebProxy) validateAndProxy(w http.ResponseWriter, r *http.Request) {
	if err := wp.validator.ValidateBearerToken(r); err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}
	wp.proxy.ServeHTTP(w, r)
}

// RegisterHandlers registers all simulator web handlers on the provided mux
// If mux is nil, registers on the default http.DefaultServeMux
func (wp *WebProxy) RegisterHandlers(mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}

	proxyHandler := http.HandlerFunc(wp.validateAndProxy)

	// Register routes that match the simulator's routes
	// Web UI
	mux.Handle("/", proxyHandler)
	mux.Handle("/ui", proxyHandler)

	// Static web assets
	mux.Handle("/web/", proxyHandler)

	// API routes
	mux.Handle("/api/v1/", proxyHandler)

	// Static files
	mux.Handle("/logo.png", proxyHandler)

	// Health check (no auth required)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Proxy health check (checks connectivity to simulator, requires auth)
	mux.HandleFunc("/proxy/health", func(w http.ResponseWriter, r *http.Request) {
		if err := wp.validator.ValidateBearerToken(r); err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		resp, err := http.Get(wp.simulatorURL.String() + "/health")
		if err != nil {
			http.Error(w, "Simulator unreachable: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Simulator health check failed", http.StatusBadGateway)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Proxy OK - Simulator OK"))
	})
}

// ProxyRequest manually proxies a single request (for custom integration)
// Note: caller should validate bearer token before calling this method
func (wp *WebProxy) ProxyRequest(w http.ResponseWriter, r *http.Request) error {
	// Validate bearer token first
	if err := wp.validator.ValidateBearerToken(r); err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return err
	}

	// Create the proxy request
	targetURL := wp.simulatorURL.String() + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		return err
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Copy status code
	w.WriteHeader(resp.StatusCode)

	// Copy body
	_, err = io.Copy(w, resp.Body)
	return err
}

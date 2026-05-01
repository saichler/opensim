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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// APIServer implementation for storage device REST APIs
func (s *APIServer) Start() error {
	if s.running {
		return nil
	}

	// Only start API server if device has API resources
	if len(s.device.resources.API) == 0 {
		return nil // No API endpoints defined, skip
	}

	addr := fmt.Sprintf("%s:%d", s.device.IP.String(), s.device.APIPort)

	// Create HTTP mux for this device's API endpoints
	mux := http.NewServeMux()

	// Group API resources by path to handle multiple methods per endpoint
	pathResources := make(map[string][]*APIResource)
	for i := range s.device.resources.API {
		resource := &s.device.resources.API[i]
		pathResources[resource.Path] = append(pathResources[resource.Path], resource)
	}

	// Register handlers for each unique path (handles all methods)
	for path, resources := range pathResources {
		// Capture resources in closure
		pathResources := resources

		// Register single handler for this path that handles all methods
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			s.handleAPIRequestMultiMethod(w, r, pathResources)
		})
	}

	// Create listener
	var listener net.Listener
	var err error
	if s.device.netNamespace != nil {
		listener, err = s.device.netNamespace.ListenTCPInNamespace("tcp", addr)
	} else {
		lc := net.ListenConfig{Control: setSocketBufferSize}
		listener, err = lc.Listen(context.Background(), "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to start API server on %s: %v", addr, err)
	}

	// Use shared TLS certificate from SimulatorManager (avoids per-device key generation)
	if s.sharedTLSCert == nil {
		return fmt.Errorf("no shared TLS certificate available for %s", addr)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*s.sharedTLSCert},
	}
	listener = tls.NewListener(listener, tlsConfig)

	s.listener = listener
	s.running = true

	// Start HTTPS server in background
	go func() {
		server := &http.Server{
			Handler: mux,
		}

		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error on %s: %v", addr, err)
		}
	}()

	// log.Printf("API server started on %s", addr)
	return nil
}

func (s *APIServer) Stop() error {
	if !s.running {
		return nil
	}

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return err
		}
	}

	s.running = false
	return nil
}

// handleAPIRequestMultiMethod processes incoming API requests that may have multiple method handlers
func (s *APIServer) handleAPIRequestMultiMethod(w http.ResponseWriter, r *http.Request, resources []*APIResource) {
	// Find the resource that matches the request method and path
	var matchedResource *APIResource

	for _, resource := range resources {
		// Check if method matches (support wildcard for all methods)
		if resource.Method == "*" || r.Method == resource.Method {
			// Handle path parameters (e.g., /api/volumes/{uuid})
			if matchPathPattern(r.URL.Path, resource.Path) {
				matchedResource = resource
				break
			}
		}
	}

	// No matching resource found
	if matchedResource == nil {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set appropriate content type
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "Storage-API-Simulator")

	// Handle authentication (basic check for Authorization header)
	if r.Header.Get("Authorization") == "" {
		// For simulation purposes, we'll be lenient and allow unauthenticated requests
		// In production, this would require proper authentication
	}

	// Extract path parameters and personalize the response
	params := extractPathParams(r.URL.Path, matchedResource.Path)
	response := personalizeResponse(matchedResource.Response, params)

	responseData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set appropriate HTTP status based on method
	switch r.Method {
	case "POST":
		w.WriteHeader(http.StatusCreated)
	case "DELETE":
		w.WriteHeader(http.StatusNoContent)
		w.Write([]byte{}) // No content for DELETE
		return
	case "PUT", "PATCH":
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusOK)
	}

	w.Write(responseData)
}

// handleAPIRequest processes incoming API requests and returns simulated responses (legacy single method)
func (s *APIServer) handleAPIRequest(w http.ResponseWriter, r *http.Request, resource *APIResource) {
	// Check if method matches (support wildcard for all methods)
	if resource.Method != "*" && r.Method != resource.Method {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle path parameters (e.g., /api/volumes/{uuid})
	requestPath := r.URL.Path
	if !matchPathPattern(requestPath, resource.Path) {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Set appropriate content type
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "Storage-API-Simulator")

	// Handle authentication (basic check for Authorization header)
	if r.Header.Get("Authorization") == "" {
		// For simulation purposes, we'll be lenient and allow unauthenticated requests
		// In production, this would require proper authentication
	}

	// Return the simulated response
	responseData, err := json.MarshalIndent(resource.Response, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set appropriate HTTP status based on method
	switch r.Method {
	case "POST":
		w.WriteHeader(http.StatusCreated)
	case "DELETE":
		w.WriteHeader(http.StatusNoContent)
		w.Write([]byte{}) // No content for DELETE
		return
	case "PUT", "PATCH":
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusOK)
	}

	w.Write(responseData)
}

// matchPathPattern checks if a request path matches a pattern with parameters
// Supports patterns like /api/volumes/{uuid} matching /api/volumes/123
func matchPathPattern(requestPath, pattern string) bool {
	// Exact match
	if requestPath == pattern {
		return true
	}

	// Split into segments
	requestSegments := strings.Split(strings.Trim(requestPath, "/"), "/")
	patternSegments := strings.Split(strings.Trim(pattern, "/"), "/")

	// Must have same number of segments
	if len(requestSegments) != len(patternSegments) {
		return false
	}

	// Match each segment
	for i := range requestSegments {
		patternSeg := patternSegments[i]
		requestSeg := requestSegments[i]

		// Check if pattern segment is a parameter (e.g., {uuid})
		if strings.HasPrefix(patternSeg, "{") && strings.HasSuffix(patternSeg, "}") {
			// Parameter - matches any value
			continue
		}

		// Must be exact match for non-parameter segments
		if patternSeg != requestSeg {
			return false
		}
	}

	return true
}

// extractPathParams extracts path parameter values from a request URL using the pattern.
// e.g., requestPath="/lynx/v1/machines/M-100003/inventory", pattern="/lynx/v1/machines/{machineId}/inventory"
// returns map["machineId"] = "M-100003"
func extractPathParams(requestPath, pattern string) map[string]string {
	params := make(map[string]string)
	reqSegs := strings.Split(strings.Trim(requestPath, "/"), "/")
	patSegs := strings.Split(strings.Trim(pattern, "/"), "/")
	if len(reqSegs) != len(patSegs) {
		return params
	}
	for i := range patSegs {
		if strings.HasPrefix(patSegs[i], "{") && strings.HasSuffix(patSegs[i], "}") {
			name := patSegs[i][1 : len(patSegs[i])-1]
			params[name] = reqSegs[i]
		}
	}
	return params
}

// personalizeResponse creates a deep copy of the response and replaces values
// based on path parameters. It replaces ID fields and varies numeric fields
// using a hash of the parameter value for realistic per-device variation.
func personalizeResponse(response interface{}, params map[string]string) interface{} {
	if len(params) == 0 {
		return response
	}

	// Marshal and unmarshal to get a mutable deep copy
	data, err := json.Marshal(response)
	if err != nil {
		return response
	}
	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return response
	}

	// Apply parameter substitution recursively
	return substituteParams(result, params)
}

func substituteParams(value interface{}, params map[string]string) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		for key, val := range v {
			// Replace ID fields that match a parameter name
			if paramVal, ok := params[key]; ok {
				v[key] = paramVal
				continue
			}
			// For "machineId" field, always replace if we have the param
			if key == "machineId" {
				if mid, ok := params["machineId"]; ok {
					v[key] = mid
				}
				continue
			}
			// Vary numeric fields based on the parameter hash for realistic data
			if key == "currentStock" || key == "currentStock" {
				if mid, ok := params["machineId"]; ok {
					if num, ok2 := val.(float64); ok2 {
						v[key] = varyNumber(num, mid, key)
					}
				}
				continue
			}
			// Recurse into sub-objects and arrays
			v[key] = substituteParams(val, params)
		}
	case []interface{}:
		for i, item := range v {
			v[i] = substituteParams(item, params)
		}
	}
	return value
}

// varyNumber takes a base number and varies it using a hash of the id+field
// to produce consistent but different values per machine.
func varyNumber(base float64, id, field string) float64 {
	h := 0
	for _, c := range id + field {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	variation := float64(h%5) - 2 // -2 to +2
	result := base + variation
	if result < 0 {
		result = 0
	}
	return result
}

package main

import (
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
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start API server on %s: %v", addr, err)
	}

	s.listener = listener
	s.running = true

	// Start HTTP server in background
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

	// Return the simulated response
	responseData, err := json.MarshalIndent(matchedResource.Response, "", "  ")
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

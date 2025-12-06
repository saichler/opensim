package main

import (
	"encoding/csv"
	"fmt"
	"log"
	mathrand "math/rand"
	"os"
)

// Global list of world cities loaded from CSV file
var worldCities []string

// loadWorldCities loads cities from worldcities.csv file
func loadWorldCities() error {
	file, err := os.Open("worldcities.csv")
	if err != nil {
		log.Printf("Failed to open worldcities.csv, using fallback cities: %v", err)
		// Fallback to a smaller set of cities if CSV file is not available
		worldCities = []string{
			"Tokyo, Japan",
			"New York, NY, USA",
			"London, England, UK",
			"Paris, France",
			"Sydney, Australia",
			"Berlin, Germany",
			"Singapore, Singapore",
			"Mumbai, India",
			"São Paulo, Brazil",
			"Moscow, Russia",
		}
		return nil
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV: %v", err)
	}

	// Skip header row and extract city and country information
	// Use a map to ensure uniqueness and avoid duplicate city-country combinations
	uniqueLocations := make(map[string]bool)

	for i, record := range records {
		if i == 0 || len(record) < 5 {
			continue // Skip header or malformed rows
		}

		city := record[0]    // city name
		country := record[4] // country name
		adminName := ""
		if len(record) > 7 {
			adminName = record[7] // admin_name (state/province)
		}

		// Create location string with more detail for disambiguation
		var location string
		if adminName != "" && adminName != city && adminName != country {
			// Include state/province for better distinction (e.g., "Boston, Massachusetts, United States")
			location = fmt.Sprintf("%s, %s, %s", city, adminName, country)
		} else {
			// Simple city, country format
			location = fmt.Sprintf("%s, %s", city, country)
		}

		// Only add if we haven't seen this exact location before
		if !uniqueLocations[location] {
			uniqueLocations[location] = true
		}
	}

	// Convert map keys to slice
	worldCities = make([]string, 0, len(uniqueLocations))
	for location := range uniqueLocations {
		worldCities = append(worldCities, location)
	}

	log.Printf("Loaded %d cities from worldcities.csv", len(worldCities))
	return nil
}

// getRandomCity returns a random city from the world cities list
func getRandomCity() string {
	// Ensure cities are loaded
	if len(worldCities) == 0 {
		log.Printf("Warning: worldCities not loaded, loading fallback cities")
		err := loadWorldCities()
		if err != nil {
			log.Printf("Error loading cities: %v", err)
		}
	}

	if len(worldCities) == 0 {
		return "Unknown Location"
	}

	return worldCities[mathrand.Intn(len(worldCities))]
}

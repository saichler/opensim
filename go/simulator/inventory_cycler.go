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
	"math"
	"time"
)

const (
	inventoryCycleDuration = 6 * time.Hour
	// Depletion rate categories
	depletionFast   = 1.0 // 100% depleted by end of cycle
	depletionNormal = 0.7 // 70% depleted
	depletionSlow   = 0.4 // 40% depleted
	// Jitter: ±15 minutes expressed as fraction of cycle
	jitterMaxFraction = 15.0 / 360.0 // 15 min / 360 min
)

var depletionRates = []float64{depletionFast, depletionNormal, depletionSlow}

// InventoryCycler computes time-based stock depletion for vending machine slots.
// Stock decreases linearly over a 6-hour cycle then resets to full (simulating restock).
// No goroutines or timers — uses time.Now() on each call.
type InventoryCycler struct {
	cycleDuration time.Duration
	startTime     time.Time
}

// NewInventoryCycler creates a cycler anchored to the current time.
func NewInventoryCycler() *InventoryCycler {
	return &InventoryCycler{
		cycleDuration: inventoryCycleDuration,
		startTime:     time.Now(),
	}
}

// GetStock returns the current stock level for a slot based on elapsed time.
// Each machineId+slotIndex combination gets a deterministic depletion rate and jitter.
func (ic *InventoryCycler) GetStock(capacity float64, machineId string, slotIndex int) float64 {
	elapsed := time.Since(ic.startTime) % ic.cycleDuration
	progress := float64(elapsed) / float64(ic.cycleDuration) // 0.0 → 1.0

	// Deterministic depletion rate from hash of machineId + slotIndex
	h := slotHash(machineId, slotIndex, "rate")
	rate := depletionRates[h%len(depletionRates)]

	// Per-slot jitter: shift progress by ±15 minutes
	jh := slotHash(machineId, slotIndex, "jitter")
	jitter := (float64(jh%100)/100.0*2.0 - 1.0) * jitterMaxFraction // -0.0417 to +0.0417
	progress = progress + jitter
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}

	stock := capacity * (1.0 - rate*progress)
	stock = math.Round(stock)
	if stock < 0 {
		stock = 0
	}
	if stock > capacity {
		stock = capacity
	}
	return stock
}

// slotHash produces a deterministic non-negative integer from machineId, slotIndex, and a salt.
func slotHash(machineId string, slotIndex int, salt string) int {
	h := 0
	for _, c := range machineId {
		h = h*31 + int(c)
	}
	h = h*31 + slotIndex
	for _, c := range salt {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

# Plan: Time-Based Inventory Cycling for Vending Simulators

## Goal

Vending machine inventory should be alive — stock levels gradually decrease over time (simulating sales) and reset to full every 6 hours (simulating a restock). Each API request returns a different stock snapshot based on when it's called, matching how CPU/memory metrics change on network device simulators.

## Current State

- `MetricsCycler` (network devices): Pre-generates 100 data points per metric. Each SNMP request advances an atomic index. Pull-based, no timers.
- `varyNumber` (vending inventory): Static hash of `machineId + slotId` → always returns the same stock value. Never changes between requests.

## Design

### Time-Based Pull Model (No Goroutines)

Use `time.Now()` to determine position in the 6-hour cycle on each API request. No tickers, no goroutines, no per-device state mutation — just a pure function:

```
elapsed = time.Now() % 6h
progress = elapsed / 6h          // 0.0 → 1.0
stock = capacity × (1.0 - depletionRate × progress)
```

At progress=0.0 (just restocked): stock = capacity
At progress=0.5 (3 hours in): stock ≈ half
At progress=1.0 (6 hours): stock ≈ 0, then resets

### Per-Slot Depletion Rates

Not all products sell at the same speed. Each slot gets a deterministic depletion rate based on a hash of `machineId + slotNumber`:

| Rate Category | Depletion | Meaning |
|---|---|---|
| Fast seller | 100% depleted by 6h | Sells out before restock (water, cola) |
| Normal seller | 70% depleted by 6h | Low stock near end of cycle |
| Slow seller | 40% depleted by 6h | Still has stock at restock time |

### Jitter

Add small per-slot jitter so stock levels don't decrease in perfect lockstep across slots. Hash-based offset shifts each slot's progress by ±15 minutes within the cycle.

## Files to Change

### 1. New file: `go/simulator/inventory_cycler.go`

```go
type InventoryCycler struct {
    cycleDuration time.Duration
    startTime     time.Time
}

func NewInventoryCycler() *InventoryCycler
func (ic *InventoryCycler) GetStock(capacity float64, machineId string, slotIndex int) float64
```

### 2. `go/simulator/types.go`

Add `inventoryCycler *InventoryCycler` field to `DeviceSimulator`.

### 3. `go/simulator/device.go`

Initialize the cycler for vending resource types (nayax_cloud, tcn_zk, afen) in both sequential and parallel device creation paths.

### 4. `go/simulator/api.go`

**Call site (line 152):** Pass the cycler from the device into `personalizeResponse`:
```go
response := personalizeResponse(matchedResource.Response, params, s.device.inventoryCycler)
```

**Function signature:** Add `*InventoryCycler` parameter:
```go
func personalizeResponse(response interface{}, params map[string]string, invCycler *InventoryCycler) interface{}
```

**Stock variation block:** Replace the `varyNumber` call with the cycler when available:
```go
if invCycler != nil {
    newStock = invCycler.GetStock(cap, mid, i)
} else {
    newStock = varyNumber(stock, mid, fmt.Sprintf("slot%d", i))
}
```

The `varyNumber` fallback handles non-vending devices that happen to have a `slots` field (unlikely but safe).

## What Does NOT Change

- Slot count variation (hash-based per machineId) — stays as-is
- Slot product names, SKUs, prices, capacities — stay from template
- The `varyNumber` function — kept for any non-inventory uses
- MetricsCycler — completely separate, unaffected
- Non-vending API responses — unaffected (inventoryCycler is nil)
- Status assignment and emptySlots/lowStockSlots recalculation — already works from whatever newStock is set

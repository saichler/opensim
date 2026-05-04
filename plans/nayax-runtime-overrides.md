# Nayax Cloud Simulator: Runtime Data Overrides

## Goal
Allow modifying machine/inventory data on a running Nayax Cloud simulator via PUT/POST requests, so changes take effect immediately without restarting.

## Current Architecture
- JSON templates loaded once at startup into `resourcesCache`
- Each request gets a deep copy via `personalizeResponse` — cached template never modified
- PUT/POST handlers return static responses without storing anything
- `personalizeResponse` applies hash-based stock variation and slot count truncation

## Design

### 1. Override Store (types.go)

Add a per-device override map to `APIServer` or `DeviceSimulator`:

```go
// Key: endpointPath (e.g., "/lynx/v1/machines/M-100003/inventory")
// Value: the overridden response data
overrides map[string]interface{}
mu        sync.RWMutex
```

### 2. PUT/POST Handlers Write to Store (api.go)

Currently in `handleAPIRequestMultiMethod`, PUT/POST return a static template response. Change to:

1. Read the request body (`json.Decode` into `map[string]interface{}`)
2. Resolve the canonical key from the request path (e.g., `/lynx/v1/machines/M-100003/inventory`)
3. Merge the incoming data with the existing response (template or previous override) — partial update semantics so callers can send only changed fields
4. Store the merged result in the override map
5. Return the merged result

### 3. Response Lookup Checks Overrides First (api.go)

Change the GET response pipeline from:

```
template response → personalizeResponse → send
```

To:

```
check overrides[resolvedPath]
  → if found: use override (skip personalizeResponse variation)
  → else: use template → personalizeResponse → send
```

Overridden data should NOT go through `personalizeResponse` stock/slot variation — if you explicitly set a value, the hash-based variation should not alter it. MachineId replacement in nested objects should still apply.

### 4. Optional: Persistence (new file, e.g., persistence.go)

Without persistence, overrides are lost on restart. To persist:

- On each override write, serialize the full override map to a JSON file (e.g., `overrides-<deviceId>.json` alongside the resource directory)
- On startup, check for an overrides file and load it into the map
- Alternatively, a simple `DELETE /admin/overrides` endpoint to clear all overrides

### Files to Change

| File | Change |
|------|--------|
| `types.go` | Add `overrides` map + mutex to `APIServer` struct |
| `api.go` | PUT/POST: parse body, merge, store in overrides |
| `api.go` | GET: check overrides before falling back to template |
| `api.go` | Skip `personalizeResponse` variation for overridden responses |
| (optional) `persistence.go` | Save/load overrides to/from disk |

### Merge Strategy

Partial merge (recommended): caller sends only the fields to change, they get merged onto the existing response. This allows updating a single slot's stock without resending the entire inventory.

Deep merge rules:
- Scalar fields: incoming value replaces existing
- Objects: recursive merge
- Arrays (like `slots`): replace entire array (merging individual array elements by index is fragile)

### Example Usage

```bash
# Update stock for machine M-100003's inventory
curl -X PUT https://localhost:8443/lynx/v1/machines/M-100003/inventory \
  -H "Content-Type: application/json" \
  -d '{
    "slots": [
      { "slotNumber": 1, "currentStock": 0, "status": "empty" },
      { "slotNumber": 2, "currentStock": 10, "status": "ok" }
    ],
    "totalSlots": 2,
    "emptySlots": 1,
    "lowStockSlots": 0
  }'

# Subsequent GETs for M-100003 inventory return the overridden data
curl https://localhost:8443/lynx/v1/machines/M-100003/inventory
```

### Estimated Scope
~50-80 lines of Go for the core (override store + handler changes). Persistence adds ~40 more.

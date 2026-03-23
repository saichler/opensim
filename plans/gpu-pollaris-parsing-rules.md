# Plan: GPU Device Pollaris and Parsing Rules for l8parser

## Context

The opensim simulator already generates GPU device data (SNMP mock data, REST API, SSH) for NVIDIA DGX/HGX servers. A GPU protobuf model (`GpuDevice`) is planned for probler (see `opensim/plans/gpu-device-proto-model.md`). This plan creates the polling definitions (pollaris) and any new parsing rules in **l8parser** to collect SNMP data from GPU devices and populate the `GpuDevice` model — following the same patterns used for `NetworkDevice` (vendor-specific pollaris) and `Cluster` (K8s pollaris).

**Prerequisite:** The `GpuDevice` proto messages must be added to `probler/proto/inventory.proto` and bindings generated before these rules can be tested end-to-end.

## Target Project

`/home/saichler/proj/src/github.com/saichler/l8parser/go/parser/boot/`

---

## SNMP OID Inventory (from opensim mock data)

### NVIDIA Enterprise OID Prefix: `1.3.6.1.4.1.53246`
- **sysObjectID:** `1.3.6.1.4.1.53246.1.2.1` (used for vendor detection)

### Module-Level (singleton)
| OID | Field |
|-----|-------|
| `53246.1.1.1.0.1.0` | GPU Count |
| `53246.1.1.1.0.2.0` | DCGM Version |

### Per-GPU Static Info (index 0-7)
| OID Pattern `53246.1.1.1.1.{X}.{gpu}` | X | Field |
|---|---|---|
| `.1.{gpu}` | 1 | Device Name |
| `.2.{gpu}` | 2 | UUID |
| `.3.{gpu}` | 3 | Serial Number |
| `.4.{gpu}` | 4 | PCI Bus ID |
| `.13.{gpu}` | 13 | Driver Version |
| `.14.{gpu}` | 14 | CUDA Version |
| `.15.{gpu}` | 15 | ECC Corrected Count |
| `.16.{gpu}` | 16 | ECC Uncorrected Count |
| `.17.{gpu}` | 17 | Power State |

### Per-GPU Dynamic Metrics (from plan, OIDs 5-12)
| OID Pattern | X | Field | Rule Type |
|---|---|---|---|
| `.5.{gpu}` | 5 | GPU Utilization % | SetTimeSeries |
| `.6.{gpu}` | 6 | VRAM Used MiB | SetTimeSeries |
| `.7.{gpu}` | 7 | Temperature C | SetTimeSeries |
| `.8.{gpu}` | 8 | Power Draw W | SetTimeSeries |
| `.9.{gpu}` | 9 | Fan Speed % | SetTimeSeries |
| `.10.{gpu}` | 10 | SM Clock MHz | SetTimeSeries |
| `.11.{gpu}` | 11 | Memory Clock MHz | SetTimeSeries |
| `.12.{gpu}` | 12 | Memory Utilization % | SetTimeSeries |

### Standard MIBs (system, host resources, interfaces)
- `1.3.6.1.2.1.1.*` — sysDescr, sysName, sysLocation, sysUpTime -> `gpudevice.deviceinfo.*`
- `1.3.6.1.2.1.2.2.1.*` — IF-MIB interface table -> `gpudevice.system.networkinterfaces.*`
- `1.3.6.1.2.1.25.*` — Host Resources MIB (memory, storage, CPU) -> `gpudevice.system.*`

---

## Implementation Phases

### Phase 1: New Parsing Rule — `SnmpGpuTable`

**New file:** `l8parser/go/parser/rules/SnmpGpuTable.go`

The NVIDIA GPU SNMP data uses indexed OIDs: `{base}.{metric_id}.{gpu_index}`. Existing table rules (`EntityMibToPhysicals`, `IfTableToPhysicals`) are hardcoded for `NetworkDevice`. We need a new rule that:

1. Receives a walked CMap of NVIDIA GPU OIDs
2. Groups entries by GPU index (0-7)
3. Maps each metric OID suffix to the corresponding `gpudevice.gpus.*` property
4. Uses `Set` for static fields, `SetTimeSeries` for dynamic metrics

**Interface:**
- **Name:** `"SnmpGpuTable"`
- **Params:**
  - `oid_base` — base OID prefix (e.g., `1.3.6.1.4.1.53246.1.1.1.1`)
  - `mapping` — comma-separated `oidSuffix:propertyName:type` triples (e.g., `1:devicename:set,2:deviceuuid:set,5:gpuutilizationpercent:ts`)
- **Logic:** Iterate CMap keys, extract `{metric_id}` and `{gpu_index}` from the OID, create/populate the Gpu repeated element at that index with the mapped property

### Phase 2: New Pollaris File — `nvidia.go`

**New file:** `l8parser/go/parser/boot/nvidia.go`

Factory function: `CreateNvidiaGpuBootPolls() *l8tpollaris.L8Pollaris`

```
Pollaris Name: "nvidia-gpu"
Groups: ["nvidia", "nvidia-gpu"]
```

**Polls to create:**

#### Poll 1: `nvidiaSystem` — Device Info (standard MIBs)
- **What:** `.1.3.6.1.2.1.1` (system MIB)
- **Operation:** `L8C_Map`
- **Cadence:** DEFAULT_CADENCE
- **Attributes:**
  - `gpudevice.deviceinfo.hostname` <- Set from `.1.3.6.1.2.1.1.5.0` (sysName)
  - `gpudevice.deviceinfo.vendor` <- Contains "53246" -> "NVIDIA"
  - `gpudevice.deviceinfo.location` <- Set from `.1.3.6.1.2.1.1.6.0` (sysLocation)
  - `gpudevice.deviceinfo.uptime` <- Set from `.1.3.6.1.2.1.1.3.0` (sysUpTime)
  - `gpudevice.deviceinfo.devicestatus` <- MapToDeviceStatus
  - `gpudevice.deviceinfo.osversion` <- Contains from sysDescr (parse OS info)
  - `gpudevice.deviceinfo.kernelversion` <- Contains from sysDescr (parse kernel)

#### Poll 2: `nvidiaGpuModule` — GPU Count & DCGM Version
- **What:** `.1.3.6.1.4.1.53246.1.1.1.0` (NVIDIA module)
- **Operation:** `L8C_Map`
- **Cadence:** DEFAULT_CADENCE
- **Attributes:**
  - `gpudevice.deviceinfo.gpucount` <- Set from `.1.3.6.1.4.1.53246.1.1.1.0.1.0`
  - `gpudevice.deviceinfo.dcgmversion` <- Set from `.1.3.6.1.4.1.53246.1.1.1.0.2.0`

#### Poll 3: `nvidiaGpuInfo` — Per-GPU Static Info
- **What:** `.1.3.6.1.4.1.53246.1.1.1.1` (NVIDIA GPU table)
- **Operation:** `L8C_Map`
- **Cadence:** DEFAULT_CADENCE
- **Attributes:** Single attribute using `SnmpGpuTable` rule with mapping for static fields:
  - `gpudevice.gpus` <- SnmpGpuTable(mapping: `1:devicename:set,2:deviceuuid:set,3:serialnumber:set,4:pcibusid:set,13:driverversion:set,14:cudaversion:set,15:ecccorrectedcount:set,16:eccuncorrectedcount:set,17:powerstate:set`)

#### Poll 4: `nvidiaGpuMetrics` — Per-GPU Dynamic Metrics
- **What:** `.1.3.6.1.4.1.53246.1.1.1.1` (same table, different cadence)
- **Operation:** `L8C_Map`
- **Cadence:** EVERY_5_MINUTES_ALWAYS (metrics need frequent polling)
- **Attributes:** Single attribute using `SnmpGpuTable` rule with mapping for time-series fields:
  - `gpudevice.gpus` <- SnmpGpuTable(mapping: `5:gpuutilizationpercent:ts,6:vramusedmib:ts,7:temperaturecelsius:ts,8:powerdrawwatts:ts,9:fanspeedpercent:ts,10:smclockmhz:ts,11:memclockmhz:ts,12:memoryutilizationpercent:ts`)

#### Poll 5: `nvidiaHostResources` — Host CPU/Memory/Storage
- **What:** `.1.3.6.1.2.1.25` (Host Resources MIB)
- **Operation:** `L8C_Map`
- **Cadence:** DEFAULT_CADENCE
- **Attributes:**
  - `gpudevice.system.memorytotalbytes` <- Set from `.1.3.6.1.2.1.25.2.2.0` (hrMemorySize)
  - `gpudevice.system.cpumodel` <- Set from `.1.3.6.1.2.1.25.3.2.1.3.1` (hrDeviceDescr, CPU entry)
  - `gpudevice.system.cpuutilizationpercent` <- SetTimeSeries from `.1.3.6.1.2.1.25.3.3.1.2.1`
  - `gpudevice.system.storagedescription` <- Set from `.1.3.6.1.2.1.25.2.3.1.3.2` (storage descr)
  - `gpudevice.system.storagetotalbytes` <- Set from `.1.3.6.1.2.1.25.2.3.1.5.2` (storage size)
  - `gpudevice.system.storageusedbytes` <- SetTimeSeries from `.1.3.6.1.2.1.25.2.3.1.6.2`

#### Poll 6: `nvidiaInterfaces` — Network Interfaces
- **What:** `.1.3.6.1.2.1.2.2.1` (IF-MIB)
- **Operation:** `L8C_Table`
- **Cadence:** EVERY_15_MINUTES_ALWAYS
- **Attributes:** Uses existing table-to-map pattern to populate `gpudevice.system.networkinterfaces.*`

### Phase 3: Updates to `SNMP.go`

1. **Add `isNvidiaOid()` function:**
   ```go
   func isNvidiaOid(sysOid string) bool {
       normalizedOid := sysOid
       if !strings.HasPrefix(normalizedOid, ".") {
           normalizedOid = "." + sysOid
       }
       return strings.HasPrefix(normalizedOid, ".1.3.6.1.4.1.53246.")
   }
   ```

2. **Add NVIDIA to `GetPollarisByOid()` waterfall** — before the default fallback:
   ```go
   if isNvidiaOid(sysOid) {
       return CreateNvidiaGpuBootPolls()
   }
   ```

3. **Add NVIDIA to `GetAllPolarisModels()`** — append `CreateNvidiaGpuBootPolls()` to the returned slice.

### Phase 4: Updates to `ParsingRule.go`

Add GpuDevice collection field mappings to `injectIndexOrKey()`:

```go
// GpuDevice collections
"gpus":               "{2}0",    // repeated Gpu
"networkinterfaces":  "{2}0",    // repeated GpuNetworkInterface (inside GpuDeviceSystem)
"gpu_links":          "{2}0",    // repeated GpuLink (inside GpuTopology)
"checks":             "{2}0",    // repeated GpuHealthCheck (inside GpuDeviceHealth)
```

### Phase 5: Register Rule

Register the new `SnmpGpuTable` rule in `l8parser/go/parser/service/Parser.go` inside `newParser()`, following the existing pattern:

```go
snmpGpuTable := &rules.SnmpGpuTable{}
p.rules[snmpGpuTable.Name()] = snmpGpuTable
```

---

## Files to Create
| File | Purpose |
|------|---------|
| `l8parser/go/parser/boot/nvidia.go` | NVIDIA GPU pollaris factory (~200 lines) |
| `l8parser/go/parser/rules/SnmpGpuTable.go` | Custom parsing rule for GPU table OIDs (~150 lines) |

## Files to Modify
| File | Change |
|------|--------|
| `l8parser/go/parser/boot/SNMP.go` | Add `isNvidiaOid()`, update `GetPollarisByOid()`, update `GetAllPolarisModels()` |
| `l8parser/go/parser/rules/ParsingRule.go` | Add GPU collection mappings to `injectIndexOrKey()` |
| `l8parser/go/parser/service/Parser.go` | Register `SnmpGpuTable` rule in `newParser()` alongside existing rules |

## Verification

1. `cd l8parser && go build ./...` — verify compilation
2. `go vet ./...` — verify no issues
3. Verify `GetAllPolarisModels()` includes the NVIDIA pollaris
4. Verify `GetPollarisByOid("1.3.6.1.4.1.53246.1.2.1")` returns the NVIDIA pollaris
5. End-to-end test requires the GpuDevice proto model to be implemented first

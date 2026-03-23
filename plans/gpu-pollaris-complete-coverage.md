# Plan: Complete GPU Device Pollaris Coverage (SNMP + SSH + REST)

## Context

The initial NVIDIA GPU pollaris (`nvidia.go`) covers ~50% of GpuDevice attributes via SNMP. This plan adds the missing SNMP mappings and introduces SSH and REST polls to achieve full coverage of all `GpuDevice` protobuf fields.

**Target project:** `l8parser/go/parser/boot/nvidia.go` and new parsing rules.

**Data sources (from opensim mock data):**
- SNMP: OIDs under `1.3.6.1.4.1.53246.*` + standard MIBs
- SSH: 10 commands (`nvidia-smi`, `nvidia-smi -q -d *`, `dcgmi *`, `show version`, `lscpu`)
- REST: 7 endpoints (`/api/v1/gpu/*`, `/api/v1/dcgm/*`, `/api/v1/system/*`)

---

## Gap Analysis

### GpuDeviceInfo — 5 fields missing

| Field | Source | Protocol | Command/OID/Endpoint |
|-------|--------|----------|---------------------|
| model | REST | RESTCONF | `/api/v1/system/info` → `gpu_model` |
| serial_number | SSH | SSH | `dmidecode -s system-serial-number` or from `show version` |
| ip_address | — | — | Set by collector (not polled) |
| kernel_version | SSH | SSH | `uname -a` → parse kernel version |
| cuda_version | SNMP | SNMPV2 | OID `.53246.1.1.1.1.14.0` (GPU 0, already in table but not at device level) |
| last_seen | — | — | Set by collector timestamp |
| latitude/longitude | — | — | Manual config (not polled) |

### GpuDeviceSystem — 4 fields missing

| Field | Source | Protocol | Command/Endpoint |
|-------|--------|----------|-----------------|
| cpu_sockets | SSH | SSH | `lscpu` → parse "Socket(s)" |
| cpu_cores_total | SSH | SSH | `lscpu` → parse "CPU(s)" |
| memory_used_bytes | SNMP | SNMPV2 | HR MIB `.1.3.6.1.2.1.25.2.3.1.6.1` (storage index 1 = Physical Memory) |
| memory_free_bytes | — | — | Computed: total - used (or from REST `/api/v1/system/memory`) |
| power_supplies | REST | RESTCONF | `/api/v1/system/info` (if available) |
| fans | REST | RESTCONF | `/api/v1/system/info` (if available) |

### Gpu (per-GPU) — 11 fields missing

| Field | Source | Protocol | Command/Endpoint |
|-------|--------|----------|-----------------|
| gpu_index | SNMP | SNMPV2 | Implicit from OID index — set in SnmpGpuTable rule |
| compute_capability | REST | RESTCONF | `/api/v1/gpu/devices` → `compute_capability` |
| persistence_mode | REST | RESTCONF | `/api/v1/gpu/devices` → `persistence_mode` |
| numa_node | REST | RESTCONF | `/api/v1/gpu/topology` → `numa_affinity` |
| vram_total_mib | REST | RESTCONF | `/api/v1/gpu/devices` → `memory_total_mib` |
| encoder_utilization_percent | SSH | SSH | `nvidia-smi -q -d UTILIZATION` → "Encoder" |
| decoder_utilization_percent | SSH | SSH | `nvidia-smi -q -d UTILIZATION` → "Decoder" |
| memory_temperature_celsius | SSH | SSH | `nvidia-smi -q -d TEMPERATURE` → "GPU Memory Temp" |
| shutdown_temperature | SSH | SSH | `nvidia-smi -q -d TEMPERATURE` → "GPU Shutdown Temp" |
| slowdown_temperature | SSH | SSH | `nvidia-smi -q -d TEMPERATURE` → "GPU Slowdown Temp" |
| power_limit_watts | SSH | SSH | `nvidia-smi -q -d POWER` → "Default Power Limit" |
| sm_clock_base_mhz | REST | RESTCONF | `/api/v1/gpu/devices` (if available) |
| mem_clock_base_mhz | REST | RESTCONF | `/api/v1/gpu/devices` (if available) |
| health (GpuComponentHealth) | REST | RESTCONF | `/api/v1/dcgm/health` → per-check status |
| processes | SSH | SSH | `nvidia-smi` → process table at bottom |

### GpuTopology — entirely missing

| Field | Source | Protocol | Command/Endpoint |
|-------|--------|----------|-----------------|
| nvlink_version | REST | RESTCONF | `/api/v1/gpu/topology` → `nvlink_version` |
| nvswitch_count | REST | RESTCONF | `/api/v1/gpu/topology` → `nvswitch_count` |
| gpu_links | REST | RESTCONF | `/api/v1/gpu/topology` → `connectivity` array |

### GpuDeviceHealth — entirely missing

| Field | Source | Protocol | Command/Endpoint |
|-------|--------|----------|-----------------|
| overall_status | REST | RESTCONF | `/api/v1/dcgm/health` → `overall_health` |
| checks | REST | RESTCONF | `/api/v1/dcgm/health` → `checks` object |

---

## Implementation Phases

### Phase 1: Fix Missing SNMP Attributes in Existing Polls

**File:** `l8parser/go/parser/boot/nvidia.go`

Add to existing polls:

1. **`nvidiaGpuModule` poll** — add `cuda_version` from GPU 0:
   - `gpudevice.deviceinfo.cudaversion` ← Set from `.1.3.6.1.4.1.53246.1.1.1.1.14.0`

2. **`nvidiaHostResources` poll** — add memory used:
   - `gpudevice.system.memoryusedbytes` ← SetTimeSeries from `.1.3.6.1.2.1.25.2.3.1.6.1` (Physical Memory used)

3. **`SnmpGpuTable` rule update** — set `gpu_index` explicitly:
   - Currently the rule populates GPU fields but doesn't set the `gpuindex` field itself
   - Add logic in `SnmpGpuTable.Parse()` to set `gpudevice.gpus.gpuindex` = gpu_index from OID

### Phase 2: New SSH Parsing Rules

**New file:** `l8parser/go/parser/rules/SshNvidiaSmiParse.go` (~200 lines)

A parsing rule that handles nvidia-smi subcommand outputs. Uses a `format` parameter to select the parser:

- **Name:** `"SshNvidiaSmiParse"`
- **Params:** `format` — one of: `utilization`, `temperature`, `power`, `version`, `lscpu`

Each format parser extracts per-GPU data from the structured nvidia-smi text output.

#### Format: `utilization` (from `nvidia-smi -q -d UTILIZATION`)
Parses per-GPU blocks, extracts:
- `encoder_utilization_percent` per GPU
- `decoder_utilization_percent` per GPU

#### Format: `temperature` (from `nvidia-smi -q -d TEMPERATURE`)
Parses per-GPU blocks, extracts:
- `memory_temperature_celsius` per GPU
- `shutdown_temperature` per GPU (static)
- `slowdown_temperature` per GPU (static)

#### Format: `power` (from `nvidia-smi -q -d POWER`)
Parses per-GPU blocks, extracts:
- `power_limit_watts` per GPU (static)

#### Format: `version` (from `show version`)
Parses key-value output, extracts:
- `gpudevice.deviceinfo.kernelversion`
- `gpudevice.deviceinfo.model` (from DGX/HGX Software line)
- `gpudevice.deviceinfo.serialnumber` (if present)

#### Format: `lscpu` (from `lscpu`)
Parses key-value output, extracts:
- `gpudevice.system.cpusockets`
- `gpudevice.system.cpucorestotal`

**New file:** `l8parser/go/parser/rules/RestJsonParse.go` (~150 lines)

A generic parsing rule that extracts fields from JSON REST API responses using dot-path notation.

- **Name:** `"RestJsonParse"`
- **Params:** `mapping` — comma-separated `jsonPath:propertyId` pairs
  - Example: `overall_health:gpudevice.health.overallstatus,nvlink_version:gpudevice.topology.nvlinkversion`

This rule deserializes the JSON response and walks the dot-paths to extract values, then sets them on the target properties. For array fields (like `connectivity`, `checks`), it iterates and populates repeated fields.

### Phase 3: New SSH Polls in `nvidia.go`

**File:** `l8parser/go/parser/boot/nvidia.go`

Add SSH polls using `L8PSSH` protocol:

#### Poll 7: `nvidiaGpuUtilization` — Encoder/Decoder utilization
- **Protocol:** L8PSSH
- **What:** `nvidia-smi -q -d UTILIZATION`
- **Cadence:** EVERY_5_MINUTES_ALWAYS
- **Rule:** SshNvidiaSmiParse(format: "utilization")
- **PropertyId:** `gpudevice.gpus`

#### Poll 8: `nvidiaGpuTemperature` — Memory temp, shutdown/slowdown thresholds
- **Protocol:** L8PSSH
- **What:** `nvidia-smi -q -d TEMPERATURE`
- **Cadence:** EVERY_15_MINUTES_ALWAYS
- **Rule:** SshNvidiaSmiParse(format: "temperature")
- **PropertyId:** `gpudevice.gpus`

#### Poll 9: `nvidiaGpuPower` — Power limits
- **Protocol:** L8PSSH
- **What:** `nvidia-smi -q -d POWER`
- **Cadence:** DEFAULT_CADENCE
- **Rule:** SshNvidiaSmiParse(format: "power")
- **PropertyId:** `gpudevice.gpus`

#### Poll 10: `nvidiaVersion` — System versions, model, serial
- **Protocol:** L8PSSH
- **What:** `show version`
- **Cadence:** DEFAULT_CADENCE
- **Rule:** SshNvidiaSmiParse(format: "version")
- **PropertyId:** `gpudevice.deviceinfo`

#### Poll 11: `nvidiaCpuInfo` — CPU sockets, cores
- **Protocol:** L8PSSH
- **What:** `lscpu`
- **Cadence:** DEFAULT_CADENCE
- **Rule:** SshNvidiaSmiParse(format: "lscpu")
- **PropertyId:** `gpudevice.system`

### Phase 4: New REST Polls in `nvidia.go`

**File:** `l8parser/go/parser/boot/nvidia.go`

Add REST polls using `L8PRESTCONF` protocol:

#### Poll 12: `nvidiaGpuDevices` — Static GPU device info
- **Protocol:** L8PRESTCONF
- **What:** `/api/v1/gpu/devices`
- **Cadence:** DEFAULT_CADENCE
- **Rule:** RestJsonParse
- **Mapping:** Per-GPU: `compute_capability`, `persistence_mode`, `memory_total_mib`
- **PropertyId:** `gpudevice.gpus`

#### Poll 13: `nvidiaGpuTopology` — NVLink topology
- **Protocol:** L8PRESTCONF
- **What:** `/api/v1/gpu/topology`
- **Cadence:** DEFAULT_CADENCE
- **Rule:** RestJsonParse
- **Mapping:** `nvlink_version`, `nvswitch_count`, `connectivity` array → `gpu_links`
- **PropertyId:** `gpudevice.topology`

#### Poll 14: `nvidiaDcgmHealth` — Health checks
- **Protocol:** L8PRESTCONF
- **What:** `/api/v1/dcgm/health`
- **Cadence:** EVERY_5_MINUTES_ALWAYS
- **Rule:** RestJsonParse
- **Mapping:** `overall_health` → `overallstatus`, `checks` → repeated `GpuHealthCheck`
- **PropertyId:** `gpudevice.health`

#### Poll 15: `nvidiaSystemMemory` — System memory details
- **Protocol:** L8PRESTCONF
- **What:** `/api/v1/system/memory`
- **Cadence:** EVERY_15_MINUTES_ALWAYS
- **Rule:** RestJsonParse
- **Mapping:** `system_memory.free_gb` → `memoryfreesbytes`, `gpu_memory.*` (aggregate)
- **PropertyId:** `gpudevice.system`

### Phase 5: Update SnmpGpuTable Rule

**File:** `l8parser/go/parser/rules/SnmpGpuTable.go`

Add automatic `gpu_index` population: when processing each GPU's data, also set `gpudevice.gpus<{2}N>.gpuindex` = N (as uint32).

### Phase 6: Register New Rules

**File:** `l8parser/go/parser/service/Parser.go`

Register the two new rules:
```go
sshNvidiaSmiParse := &rules.SshNvidiaSmiParse{}
p.rules[sshNvidiaSmiParse.Name()] = sshNvidiaSmiParse
restJsonParse := &rules.RestJsonParse{}
p.rules[restJsonParse.Name()] = restJsonParse
```

---

## Coverage Summary After Implementation

| Section | Before | After |
|---------|--------|-------|
| GpuDeviceInfo (17 fields) | 10/17 | 15/17 (ip_address and lat/lng are config, not polled) |
| GpuDeviceSystem (13 fields) | 8/13 | 12/13 (fans/PSU depend on device support) |
| Gpu per-GPU (29 fields) | 14/29 | 28/29 (processes deferred) |
| GpuTopology (3 fields) | 0/3 | 3/3 |
| GpuDeviceHealth (2 fields) | 0/2 | 2/2 |
| **Total** | **32/64** | **60/64** |

**Remaining 4 unpolled fields:**
- `ip_address` — set by collector infrastructure, not polled
- `latitude/longitude` — manual configuration
- `last_seen` — set by collector timestamp

---

## Files to Create

| File | Purpose | Est. Lines |
|------|---------|-----------|
| `l8parser/go/parser/rules/SshNvidiaSmiParse.go` | SSH nvidia-smi/version/lscpu parser | ~300 |
| `l8parser/go/parser/rules/RestJsonParse.go` | Generic REST JSON field extractor | ~200 |

## Files to Modify

| File | Change |
|------|--------|
| `l8parser/go/parser/boot/nvidia.go` | Add 9 new polls (5 SSH + 4 REST), add missing SNMP attributes |
| `l8parser/go/parser/rules/SnmpGpuTable.go` | Auto-set `gpuindex` field |
| `l8parser/go/parser/service/Parser.go` | Register 2 new rules |

## Verification

1. `cd l8parser/go && go build ./...` — verify compilation
2. `cd l8parser/go && go vet ./...` — verify no issues
3. Count polls in `CreateNvidiaGpuBootPolls()` — should be 15 total
4. Verify all GpuDevice proto fields have a corresponding pollaris attribute
5. End-to-end test requires GpuDevice proto model to be implemented first

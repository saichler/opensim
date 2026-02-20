/*
 * Copyright 2025 Sharon Aicler (saichler@gmail.com)
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

// DeviceProfile defines CPU/memory metric parameters for a device category.
type DeviceProfile struct {
	CPUBaseMin  int   // Minimum base CPU% (e.g., 10)
	CPUBaseMax  int   // Maximum base CPU% (e.g., 40)
	CPUSpike    int   // Max amplitude of sine wave spikes
	MemTotalKB  int64 // Total memory in KB
	MemBaseMin  int   // Minimum base memory utilization %
	MemBaseMax  int   // Maximum base memory utilization %
	MemVariance int   // Memory fluctuation range %
}

var profileCoreRouter = DeviceProfile{
	CPUBaseMin: 15, CPUBaseMax: 45, CPUSpike: 20,
	MemTotalKB: 16 * 1024 * 1024, // 16 GB
	MemBaseMin: 50, MemBaseMax: 80, MemVariance: 10,
}

var profileEdgeRouter = DeviceProfile{
	CPUBaseMin: 10, CPUBaseMax: 35, CPUSpike: 18,
	MemTotalKB: 8 * 1024 * 1024, // 8 GB
	MemBaseMin: 40, MemBaseMax: 70, MemVariance: 10,
}

var profileDCSwitch = DeviceProfile{
	CPUBaseMin: 8, CPUBaseMax: 30, CPUSpike: 15,
	MemTotalKB: 16 * 1024 * 1024, // 16 GB
	MemBaseMin: 45, MemBaseMax: 75, MemVariance: 8,
}

var profileCampusSwitch = DeviceProfile{
	CPUBaseMin: 5, CPUBaseMax: 25, CPUSpike: 12,
	MemTotalKB: 4 * 1024 * 1024, // 4 GB
	MemBaseMin: 35, MemBaseMax: 65, MemVariance: 8,
}

var profileFirewall = DeviceProfile{
	CPUBaseMin: 25, CPUBaseMax: 60, CPUSpike: 25,
	MemTotalKB: 8 * 1024 * 1024, // 8 GB
	MemBaseMin: 55, MemBaseMax: 85, MemVariance: 10,
}

var profileServer = DeviceProfile{
	CPUBaseMin: 20, CPUBaseMax: 50, CPUSpike: 22,
	MemTotalKB: 32 * 1024 * 1024, // 32 GB
	MemBaseMin: 50, MemBaseMax: 80, MemVariance: 10,
}

// deviceProfileMap maps resource file names to their device profiles.
var deviceProfileMap = map[string]DeviceProfile{
	// Core Routers
	"asr9k.json":            profileCoreRouter,
	"cisco_crs_x.json":      profileCoreRouter,
	"huawei_ne8000.json":    profileCoreRouter,
	"nokia_7750_sr12.json":  profileCoreRouter,
	"juniper_mx960.json":    profileCoreRouter,

	// Edge Routers
	"juniper_mx240.json": profileEdgeRouter,
	"nec_ix3315.json":    profileEdgeRouter,
	"cisco_ios.json":     profileEdgeRouter,

	// Data Center Switches
	"cisco_nexus_9500.json": profileDCSwitch,
	"arista_7280r3.json":    profileDCSwitch,

	// Campus Switches
	"cisco_catalyst_9500.json": profileCampusSwitch,
	"extreme_vsp4450.json":     profileCampusSwitch,
	"dlink_dgs3630.json":       profileCampusSwitch,

	// Firewalls
	"palo_alto_pa3220.json":       profileFirewall,
	"fortinet_fortigate_600e.json": profileFirewall,
	"sonicwall_nsa6700.json":      profileFirewall,
	"check_point_15600.json":      profileFirewall,

	// Servers / BMC
	"dell_poweredge_r750.json": profileServer,
	"hpe_proliant_dl380.json":  profileServer,
	"ibm_power_s922.json":      profileServer,
}

// GetDeviceProfile returns the metric profile for a given resource file.
// Falls back to edge router profile if the file is unknown.
func GetDeviceProfile(resourceFile string) DeviceProfile {
	if p, ok := deviceProfileMap[resourceFile]; ok {
		return p
	}
	return profileEdgeRouter
}

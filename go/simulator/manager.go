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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	mathrand "math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SimulatorManager implementation
func NewSimulatorManager() *SimulatorManager {
	// Initialize random seed once at startup
	mathrand.Seed(time.Now().UnixNano())

	sm := &SimulatorManager{
		devices:          make(map[string]*DeviceSimulator),
		nextTunIndex:     0,
		resourcesCache:   make(map[string]*DeviceResources),
		tunInterfacePool: make(map[string]*TunInterface),
	}
	// Initialize atomic values
	sm.isPreAllocating.Store(false)
	sm.preAllocProgress.Store(0)
	sm.isCreatingDevices.Store(false)
	sm.deviceCreateProgress.Store(0)
	sm.deviceCreateTotal.Store(0)

	// Pre-generate shared SSH host key for all devices
	sm.generateSharedSSHKey()

	return sm
}

func (sm *SimulatorManager) getNextTunName() string {
	name := fmt.Sprintf("%s%d", TUN_DEVICE_PREFIX, sm.nextTunIndex)
	sm.nextTunIndex++
	return name
}

// generateSharedSSHKey generates a single RSA key to be shared by all devices
func (sm *SimulatorManager) generateSharedSSHKey() {
	log.Println("Generating shared SSH host key for all devices...")
	startTime := time.Now()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("WARNING: Failed to generate shared SSH key: %v", err)
		return
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		log.Printf("WARNING: Failed to parse shared SSH key: %v", err)
		return
	}

	sm.sharedSSHSigner = signer
	elapsed := time.Since(startTime)
	log.Printf("Shared SSH host key generated in %v", elapsed)
}

func (sm *SimulatorManager) ListDevices() []DeviceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var devices []DeviceInfo
	for _, device := range sm.devices {
		info := DeviceInfo{
			ID:         device.ID,
			IP:         device.IP.String(),
			SNMPPort:   device.SNMPPort,
			SSHPort:    device.SSHPort,
			Running:    device.running,
			DeviceType: getDeviceTypeFromResourceFile(device.resourceFile),
		}
		if device.tunIface != nil {
			info.Interface = device.tunIface.Name
		}
		devices = append(devices, info)
	}

	return devices
}

func (sm *SimulatorManager) GetStatus() ManagerStatus {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	totalDevices := len(sm.devices)
	runningDevices := 0
	for _, device := range sm.devices {
		if device.running {
			runningDevices++
		}
	}

	return ManagerStatus{
		IsPreAllocating:      sm.isPreAllocating.Load().(bool),
		PreAllocProgress:     sm.preAllocProgress.Load().(int),
		PreAllocTotal:        sm.tunPoolSize,
		IsCreatingDevices:    sm.isCreatingDevices.Load().(bool),
		DeviceCreateProgress: sm.deviceCreateProgress.Load().(int),
		DeviceCreateTotal:    sm.deviceCreateTotal.Load().(int),
		TotalDevices:         totalDevices,
		RunningDevices:       runningDevices,
	}
}

func (sm *SimulatorManager) DeleteDevice(deviceID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	device, exists := sm.devices[deviceID]
	if !exists {
		return fmt.Errorf("device %s not found", deviceID)
	}

	// Stop and cleanup device
	if err := device.Stop(); err != nil {
		// log.Printf("Error stopping device %s: %v", deviceID, err)
	}

	delete(sm.devices, deviceID)
	return nil
}

func (sm *SimulatorManager) DeleteAllDevices() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var errors []string
	var tunInterfaces []string

	// Collect all TUN interface names for bulk deletion
	for deviceID, device := range sm.devices {
		if err := device.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", deviceID, err))
		}
		// Collect TUN interface names for bulk deletion
		if device.tunIface != nil && !device.tunIface.PreAllocated {
			tunInterfaces = append(tunInterfaces, device.tunIface.Name)
		}
	}

	// Bulk delete TUN interfaces for better performance
	if len(tunInterfaces) > 0 {
		if err := sm.bulkDeleteTunInterfaces(tunInterfaces); err != nil {
			errors = append(errors, fmt.Sprintf("bulk TUN deletion: %v", err))
		}
	}

	// Clear the devices map
	sm.devices = make(map[string]*DeviceSimulator)

	if len(errors) > 0 {
		return fmt.Errorf("errors deleting devices: %s", strings.Join(errors, ", "))
	}
	return nil
}

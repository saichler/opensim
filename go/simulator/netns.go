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
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// Network namespace name for all simulated devices
	NETNS_NAME = "opensim"
	// Veth pair names for host-namespace connectivity
	VETH_HOST = "veth-sim-host"
	VETH_NS   = "veth-sim-ns"
	// Bridge IP for host side (gateway for namespace)
	VETH_HOST_IP = "10.254.0.1"
	// Namespace side IP
	VETH_NS_IP = "10.254.0.2"
	// Network mask for veth pair
	VETH_NETMASK = "30"
)

// NetNamespace manages the network namespace for simulated devices
type NetNamespace struct {
	Name       string
	NsFd       int  // File descriptor to the namespace
	OrigNsFd   int  // Original namespace fd to return to
	Active     bool // Whether namespace is active
	VethSetup  bool // Whether veth pair is configured
}

// CreateNetNamespace creates and configures the opensim network namespace
func CreateNetNamespace() (*NetNamespace, error) {
	ns := &NetNamespace{
		Name:   NETNS_NAME,
		NsFd:   -1,
		OrigNsFd: -1,
	}

	log.Printf("Creating network namespace '%s' for device isolation...", NETNS_NAME)
	startTime := time.Now()

	// Check if namespace already exists and clean it up
	if namespaceExists(NETNS_NAME) {
		log.Printf("Network namespace '%s' already exists, cleaning up...", NETNS_NAME)
		if err := deleteNetNamespace(NETNS_NAME); err != nil {
			log.Printf("Warning: failed to clean up existing namespace: %v", err)
		}
	}

	// Create the network namespace
	cmd := exec.Command("ip", "netns", "add", NETNS_NAME)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to create namespace: %v, output: %s", err, string(output))
	}

	// Open the namespace file descriptor for later use
	nsPath := fmt.Sprintf("/var/run/netns/%s", NETNS_NAME)
	fd, err := syscall.Open(nsPath, syscall.O_RDONLY, 0)
	if err != nil {
		deleteNetNamespace(NETNS_NAME)
		return nil, fmt.Errorf("failed to open namespace fd: %v", err)
	}
	ns.NsFd = fd
	ns.Active = true

	// Bring up loopback inside namespace
	if err := ns.execInNs("ip", "link", "set", "lo", "up"); err != nil {
		log.Printf("Warning: failed to bring up loopback: %v", err)
	}

	// Setup veth pair for connectivity
	if err := ns.setupVethPair(); err != nil {
		log.Printf("Warning: veth setup failed: %v (devices may not be reachable from host)", err)
	} else {
		ns.VethSetup = true
	}

	elapsed := time.Since(startTime)
	log.Printf("Network namespace '%s' created in %v", NETNS_NAME, elapsed)

	return ns, nil
}

// setupVethPair creates a veth pair connecting host to namespace
func (ns *NetNamespace) setupVethPair() error {
	// Delete existing veth if present
	exec.Command("ip", "link", "delete", VETH_HOST).Run()

	// Create veth pair
	cmd := exec.Command("ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create veth pair: %v, output: %s", err, string(output))
	}

	// Move one end to namespace
	cmd = exec.Command("ip", "link", "set", VETH_NS, "netns", NETNS_NAME)
	if output, err := cmd.CombinedOutput(); err != nil {
		exec.Command("ip", "link", "delete", VETH_HOST).Run()
		return fmt.Errorf("failed to move veth to namespace: %v, output: %s", err, string(output))
	}

	// Configure host side
	cmd = exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", VETH_HOST_IP, VETH_NETMASK), "dev", VETH_HOST)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure host veth IP: %v, output: %s", err, string(output))
	}

	cmd = exec.Command("ip", "link", "set", VETH_HOST, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring up host veth: %v, output: %s", err, string(output))
	}

	// Configure namespace side
	if err := ns.execInNs("ip", "addr", "add", fmt.Sprintf("%s/%s", VETH_NS_IP, VETH_NETMASK), "dev", VETH_NS); err != nil {
		return fmt.Errorf("failed to configure ns veth IP: %v", err)
	}

	if err := ns.execInNs("ip", "link", "set", VETH_NS, "up"); err != nil {
		return fmt.Errorf("failed to bring up ns veth: %v", err)
	}

	// Set default route in namespace to go through veth
	if err := ns.execInNs("ip", "route", "add", "default", "via", VETH_HOST_IP); err != nil {
		log.Printf("Warning: failed to add default route in namespace: %v", err)
	}

	log.Printf("Veth pair configured: %s (%s) <-> %s (%s)", VETH_HOST, VETH_HOST_IP, VETH_NS, VETH_NS_IP)

	return nil
}

// AddRouteToNamespace adds a route on the host to reach IPs inside the namespace
func (ns *NetNamespace) AddRouteToNamespace(network string, netmask string) error {
	// Add route: traffic to the simulated network goes through the namespace veth
	cidr := fmt.Sprintf("%s/%s", network, netmask)
	cmd := exec.Command("ip", "route", "add", cidr, "via", VETH_NS_IP)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if route already exists
		if strings.Contains(string(output), "File exists") {
			return nil // Route already exists, that's fine
		}
		return fmt.Errorf("failed to add route to %s: %v, output: %s", cidr, err, string(output))
	}
	log.Printf("Added host route: %s via %s", cidr, VETH_NS_IP)
	return nil
}

// execInNs executes a command inside the network namespace
func (ns *NetNamespace) execInNs(name string, args ...string) error {
	fullArgs := append([]string{"netns", "exec", ns.Name, name}, args...)
	cmd := exec.Command("ip", fullArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %v, output: %s", err, string(output))
	}
	return nil
}

// ExecInNsOutput executes a command inside the namespace and returns output
func (ns *NetNamespace) ExecInNsOutput(name string, args ...string) ([]byte, error) {
	fullArgs := append([]string{"netns", "exec", ns.Name, name}, args...)
	cmd := exec.Command("ip", fullArgs...)
	return cmd.CombinedOutput()
}

// EnterNamespace switches the current goroutine to the network namespace
// IMPORTANT: Must call LeaveNamespace() when done, and goroutine must be locked to OS thread
func (ns *NetNamespace) EnterNamespace() error {
	if ns.NsFd < 0 {
		return fmt.Errorf("namespace not initialized")
	}

	// Lock goroutine to OS thread - required for namespace operations
	runtime.LockOSThread()

	// Save original namespace
	origFd, err := syscall.Open("/proc/self/ns/net", syscall.O_RDONLY, 0)
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to open original namespace: %v", err)
	}
	ns.OrigNsFd = origFd

	// Switch to the new namespace
	if err := unix.Setns(ns.NsFd, syscall.CLONE_NEWNET); err != nil {
		syscall.Close(origFd)
		ns.OrigNsFd = -1
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to enter namespace: %v", err)
	}

	return nil
}

// LeaveNamespace returns to the original network namespace
func (ns *NetNamespace) LeaveNamespace() error {
	if ns.OrigNsFd < 0 {
		runtime.UnlockOSThread()
		return nil
	}

	// Switch back to original namespace
	err := unix.Setns(ns.OrigNsFd, syscall.CLONE_NEWNET)
	syscall.Close(ns.OrigNsFd)
	ns.OrigNsFd = -1

	// Unlock from OS thread
	runtime.UnlockOSThread()

	if err != nil {
		return fmt.Errorf("failed to leave namespace: %v", err)
	}
	return nil
}

// Close cleans up the network namespace
func (ns *NetNamespace) Close() error {
	if !ns.Active {
		return nil
	}

	log.Printf("Cleaning up network namespace '%s'...", ns.Name)

	// Close namespace fd
	if ns.NsFd >= 0 {
		syscall.Close(ns.NsFd)
		ns.NsFd = -1
	}

	// Delete veth pair (deleting one end deletes both)
	if ns.VethSetup {
		exec.Command("ip", "link", "delete", VETH_HOST).Run()
		ns.VethSetup = false
	}

	// Delete the namespace
	if err := deleteNetNamespace(ns.Name); err != nil {
		return err
	}

	ns.Active = false
	log.Printf("Network namespace '%s' cleaned up", ns.Name)
	return nil
}

// namespaceExists checks if a network namespace exists
func namespaceExists(name string) bool {
	nsPath := fmt.Sprintf("/var/run/netns/%s", name)
	_, err := os.Stat(nsPath)
	return err == nil
}

// deleteNetNamespace deletes a network namespace
func deleteNetNamespace(name string) error {
	cmd := exec.Command("ip", "netns", "delete", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Namespace might already be gone
		if strings.Contains(string(output), "No such file") {
			return nil
		}
		return fmt.Errorf("failed to delete namespace: %v, output: %s", err, string(output))
	}
	return nil
}

// ListNamespaceInterfaces lists all interfaces in the namespace
func (ns *NetNamespace) ListNamespaceInterfaces() ([]string, error) {
	output, err := ns.ExecInNsOutput("ip", "-o", "link", "show")
	if err != nil {
		return nil, err
	}

	var interfaces []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		// Format: "1: lo: <LOOPBACK,UP,LOWER_UP> ..."
		parts := strings.SplitN(line, ":", 3)
		if len(parts) >= 2 {
			ifName := strings.TrimSpace(parts[1])
			interfaces = append(interfaces, ifName)
		}
	}
	return interfaces, nil
}

// AddRouteForDevices adds host routes to reach simulated device IPs through the namespace
// This is called automatically when devices are created to ensure external reachability
func (ns *NetNamespace) AddRouteForDevices(startIP string, count int, netmask string) error {
	if !ns.VethSetup {
		return fmt.Errorf("veth not configured, cannot add routes")
	}

	// Calculate the network ranges that need routes
	// For simplicity, we add routes for each /24 subnet that contains devices
	networks := calculateNetworkRanges(startIP, count, netmask)

	for _, network := range networks {
		if err := ns.addHostRoute(network); err != nil {
			log.Printf("Warning: failed to add route for %s: %v", network, err)
		}
	}

	return nil
}

// addHostRoute adds a single route on the host to reach a network through the namespace
func (ns *NetNamespace) addHostRoute(cidr string) error {
	// First check if route already exists
	cmd := exec.Command("ip", "route", "show", cidr)
	output, _ := cmd.CombinedOutput()
	if strings.Contains(string(output), cidr) {
		return nil // Route already exists
	}

	// Add the route
	cmd = exec.Command("ip", "route", "add", cidr, "via", VETH_NS_IP)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "File exists") {
			return nil
		}
		return fmt.Errorf("failed to add route: %v, output: %s", err, string(output))
	}

	log.Printf("Added host route: %s via %s (for external access)", cidr, VETH_NS_IP)
	return nil
}

// calculateNetworkRanges determines which network ranges need routes based on device IPs
func calculateNetworkRanges(startIP string, count int, netmask string) []string {
	ip := net.ParseIP(startIP)
	if ip == nil {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil
	}

	// Track unique /24 networks (or use provided netmask for smaller ranges)
	networks := make(map[string]bool)

	// For each device, determine its network
	currentIP := make(net.IP, 4)
	copy(currentIP, ip)

	for i := 0; i < count; i++ {
		// Get network address for this IP based on netmask
		var networkAddr string
		switch netmask {
		case "8":
			networkAddr = fmt.Sprintf("%d.0.0.0/8", currentIP[0])
		case "16":
			networkAddr = fmt.Sprintf("%d.%d.0.0/16", currentIP[0], currentIP[1])
		case "24":
			networkAddr = fmt.Sprintf("%d.%d.%d.0/24", currentIP[0], currentIP[1], currentIP[2])
		default:
			// Default to /24 for routing efficiency
			networkAddr = fmt.Sprintf("%d.%d.%d.0/24", currentIP[0], currentIP[1], currentIP[2])
		}
		networks[networkAddr] = true

		// Increment IP
		incrementIP(currentIP)
	}

	// Convert map to slice
	result := make([]string, 0, len(networks))
	for network := range networks {
		result = append(result, network)
	}

	return result
}

// incrementIP increments an IPv4 address in place
func incrementIP(ip net.IP) {
	ip[3]++
	if ip[3] == 0 || ip[3] == 255 {
		ip[2]++
		ip[3] = 1
		if ip[2] == 0 {
			ip[1]++
			if ip[1] == 0 {
				ip[0]++
			}
		}
	}
}

// RemoveRouteForDevices removes host routes when devices are deleted
func (ns *NetNamespace) RemoveRouteForDevices(startIP string, count int, netmask string) {
	networks := calculateNetworkRanges(startIP, count, netmask)
	for _, network := range networks {
		cmd := exec.Command("ip", "route", "delete", network)
		cmd.Run() // Ignore errors
	}
}

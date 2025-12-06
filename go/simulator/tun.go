package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// TUN interface management functions
func createTunInterface(name string, ip net.IP, netmask string) (*TunInterface, error) {
	// Open TUN device
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Configure interface
	ifr := make([]byte, 40)
	copy(ifr, []byte(name))
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001) // IFF_TUN

	// TUNSETIFF ioctl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl failed: %v", errno)
	}

	tun := &TunInterface{
		Name: name,
		IP:   ip,
		fd:   fd,
	}

	// Configure the interface
	if err := tun.configure(netmask); err != nil {
		tun.destroy()
		return nil, err
	}

	return tun, nil
}

// bindToTunInterface opens an existing TUN interface for use by a device
func bindToTunInterface(name string, ip net.IP) (*TunInterface, error) {
	// Open TUN device
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Bind to existing interface
	ifr := make([]byte, 40)
	copy(ifr, []byte(name))
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001) // IFF_TUN

	// TUNSETIFF ioctl to bind to existing interface
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl failed: %v", errno)
	}

	return &TunInterface{
		Name: name,
		IP:   ip,
		fd:   fd,
	}, nil
}

func (tun *TunInterface) configure(netmask string) error {
	// Configure IP address using ip command
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", tun.IP.String(), netmask), "dev", tun.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %v", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", tun.Name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %v", err)
	}

	// log.Printf("Created TUN interface %s with IP %s", tun.Name, tun.IP.String())
	return nil
}

func (tun *TunInterface) destroy() error {
	if tun.fd > 0 {
		return syscall.Close(tun.fd)
	}
	return nil
}

// reconfigure updates the IP address of an existing TUN interface
func (tun *TunInterface) reconfigure(newIP net.IP, netmask string) error {
	// Remove old IP address
	cmd := exec.Command("ip", "addr", "del", fmt.Sprintf("%s/%s", tun.IP.String(), netmask), "dev", tun.Name)
	cmd.Run() // Ignore errors in case the IP wasn't set

	// Set new IP address
	cmd = exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", newIP.String(), netmask), "dev", tun.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set new IP address %s: %v", newIP.String(), err)
	}

	// Update the interface IP
	tun.IP = make(net.IP, len(newIP))
	copy(tun.IP, newIP)

	return nil
}

// compareOIDsLexicographically compares two OID strings lexicographically
// Returns -1 if oid1 < oid2, 0 if equal, 1 if oid1 > oid2
func compareOIDsLexicographically(oid1, oid2 string) int {
	parts1 := strings.Split(oid1, ".")
	parts2 := strings.Split(oid2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var val1, val2 int

		if i < len(parts1) {
			val1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			val2, _ = strconv.Atoi(parts2[i])
		}

		if val1 < val2 {
			return -1
		} else if val1 > val2 {
			return 1
		}
	}

	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}

	return 0
}

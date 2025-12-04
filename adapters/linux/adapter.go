package linux

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go blocker blocker.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go network network.bpf.c

var (
	// App Blocker Globals
	lsmLink    link.Link
	BlockedMap *ebpf.Map

	// Network Blocker Globals
	networkLink link.Link
	AllowedIPs  *ebpf.Map
)

// Helper to safely convert string to fixed-size key
func strToKey(s string) [16]byte {
	var key [16]byte
	copy(key[:], s)
	return key
}

// SyncBlockedApps updates the kernel map with the list of forbidden app names
func SyncBlockedApps(apps []string) error {
	for _, appName := range apps {
		key := strToKey(appName)
		value := uint32(1)

		if err := BlockedMap.Put(key, value); err != nil {
			return fmt.Errorf("failed to update map: %w", err)
		}
	}
	return nil
}

// AllowIP adds a single IPv4 address to the allowlist map
func AllowIP(ipStr string) error {

	if AllowedIPs == nil {
		return nil // Just ignore it, don't crash!
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", ipStr)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("not an ipv4 address: %s", ipStr)
	}

	// Convert IP to Little Endian uint32
	ipInt := uint32(ipv4[0]) | uint32(ipv4[1])<<8 | uint32(ipv4[2])<<16 | uint32(ipv4[3])<<24
	value := uint32(1)

	if err := AllowedIPs.Put(ipInt, value); err != nil {
		return fmt.Errorf("update allowed map: %w", err)
	}
	return nil
}

// StartBlocker loads the App Blocker (LSM Hook)
func StartBlocker() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var objs blockerObjects
	if err := loadBlockerObjects(&objs, nil); err != nil {
		return fmt.Errorf("load blocker objects: %w", err)
	}

	BlockedMap = objs.BlockedApps

	var err error
	lsmLink, err = link.AttachLSM(link.LSMOptions{Program: objs.RestrictExec})
	if err != nil {
		return fmt.Errorf("attach lsm: %w", err)
	}

	return nil
}

// StartNetworkBlocker loads the Network Filter (TCX Hook)
func StartNetworkBlocker(ifaceName string) error {
	// 1. Get the Interface (e.g. "wlp1s0")
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup interface %s: %w", ifaceName, err)
	}

	// 2. Load the eBPF objects
	var objs networkObjects
	if err := loadNetworkObjects(&objs, nil); err != nil {
		return fmt.Errorf("load network objects: %w", err)
	}

	// 3. Save map handle globally
	AllowedIPs = objs.AllowedIps

	// 4. Attach to Egress (Outgoing Traffic) using TCX
	// TCX is the modern, high-performance replacement for legacy TC.
	networkLink, err = link.AttachTCX(link.TCXOptions{
		Program:   objs.EgressFilter,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attach tcx: %w", err)
	}

	return nil
}

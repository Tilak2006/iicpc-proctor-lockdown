package linux

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go blocker blocker.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go network network.bpf.c

var (
	// App Blocker Globals
	lsmLink     link.Link
	AllowedMap  *ebpf.Map // Renamed from BlockedMap
	blockerObjs *blockerObjects

	// Network Blocker Globals
	tcFilter    *netlink.BpfFilter
	AllowedIPs  *ebpf.Map
	networkObjs *networkObjects
)

// strToKey converts string to fixed-size key
func strToKey(s string) [16]byte {
	var key [16]byte
	s = strings.TrimSpace(strings.ToLower(s))
	copy(key[:], s)
	return key
}

// SyncAllowedApps updates the App Blocker map
func SyncAllowedApps(apps []string) error {
	if AllowedMap == nil {
		return nil // Safety check
	}

	// Clear map first to remove old entries
	iter := AllowedMap.Iterate()
	var key [16]byte
	var val uint32
	for iter.Next(&key, &val) {
		AllowedMap.Delete(key)
	}

	log.Printf("  → Syncing %d allowed apps to map", len(apps))
	for _, appName := range apps {
		key := strToKey(appName)
		if err := AllowedMap.Put(key, uint32(1)); err != nil {
			return fmt.Errorf("update map %q: %w", appName, err)
		}
		log.Printf("    • Added to allowlist: %s", appName)
	}
	return nil
}

// AllowIP adds an IP to the allowlist using Network Byte Order
func AllowIP(ipStr string) error {
	if AllowedIPs == nil {
		return nil // Safety check
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("not an ipv4: %s", ipStr)
	}

	// Use BigEndian to match the raw packet data in kernel
	ipInt := binary.BigEndian.Uint32(ipv4)

	if err := AllowedIPs.Put(ipInt, uint32(1)); err != nil {
		return fmt.Errorf("allow ip %s: %w", ipStr, err)
	}
	return nil
}

// StartBlocker loads the App Blocker (LSM)
func StartBlocker() error {
	log.Println("  → Removing memlock limit...")
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("memlock: %w", err)
	}

	log.Println("  → Loading eBPF objects...")
	var objs blockerObjects
	if err := loadBlockerObjects(&objs, nil); err != nil {
		return fmt.Errorf("load blocker: %w", err)
	}
	blockerObjs = &objs
	AllowedMap = objs.AllowedApps // Changed from BlockedApps

	log.Printf("  → eBPF program loaded, FD: %d", objs.RestrictExec.FD())
	log.Printf("  → Map loaded, FD: %d", objs.AllowedApps.FD())

	log.Println("  → Attaching to LSM hook bprm_check_security...")
	var err error
	lsmLink, err = link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictExec,
	})
	if err != nil {
		log.Printf("  ✗ LSM attachment failed: %v", err)
		return fmt.Errorf("attach lsm: %w", err)
	}

	log.Printf("  → LSM link created successfully")
	return nil
}

// StartNetworkBlocker loads the Network Filter (TC via netlink)
func StartNetworkBlocker(ifaceName string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("memlock: %w", err)
	}

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifaceName, err)
	}

	var objs networkObjects
	if err := loadNetworkObjects(&objs, nil); err != nil {
		return fmt.Errorf("load network: %w", err)
	}
	networkObjs = &objs
	AllowedIPs = objs.AllowedIps

	// Ensure clsact qdisc exists
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		// Ignore if already exists
		if !strings.Contains(err.Error(), "file exists") {
			return fmt.Errorf("add clsact qdisc: %w", err)
		}
	}

	// Attach TC filter to egress
	tcFilter = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.EgressFilter.FD(),
		Name:         "egress_filter",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(tcFilter); err != nil {
		return fmt.Errorf("attach tc egress: %w", err)
	}

	return nil
}

// StopBlocker detaches the App Blocker
func StopBlocker() error {
	if lsmLink != nil {
		if err := lsmLink.Close(); err != nil {
			return fmt.Errorf("close lsm link: %w", err)
		}
		lsmLink = nil
	}
	if blockerObjs != nil {
		blockerObjs.Close()
		blockerObjs = nil
	}
	AllowedMap = nil // Changed from BlockedMap
	return nil
}

// StopNetworkBlocker detaches the Network Filter
func StopNetworkBlocker() error {
	if tcFilter != nil {
		if err := netlink.FilterDel(tcFilter); err != nil {
			return fmt.Errorf("remove tc filter: %w", err)
		}
		tcFilter = nil
	}
	if networkObjs != nil {
		networkObjs.Close()
		networkObjs = nil
	}
	AllowedIPs = nil
	return nil
}

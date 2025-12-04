package linux

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go blocker blocker.bpf.c

var (
	lsmLink    link.Link
	BlockedMap *ebpf.Map
)

func strToKey(s string) [16]byte {
	var key [16]byte
	copy(key[:], s)

	return key
}

func SyncBlockedApps(apps []string) error {
	for _, appName := range apps {
		// 1. Convert the string to a key (using our helper)
		key := strToKey(appName)

		// 2. Define the value for "Blocked" (1)
		// We use uint32 because the C map defines the value as __u32
		value := uint32(1)

		// 3. Write to the kernel map
		if err := BlockedMap.Put(key, value); err != nil {
			return fmt.Errorf("failed to update map: %w", err)
		}
	}
	return nil
}

func StartBlocker() error {
	// allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	// declare the variable for the generated objects (blocked objs)
	var objs blockerObjects

	// This takes the bytecode, sends it to the kernel, and populates 'objs' with the handles
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

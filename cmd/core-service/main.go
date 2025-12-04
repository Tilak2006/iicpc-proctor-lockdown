package main

import (
	"iicpc-network/adapters/linux"
	"iicpc-network/core"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Setup graceful shutdown handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\n🛑 Shutting down gracefully...")

		// Clean up network blocker
		if err := linux.StopNetworkBlocker(); err != nil {
			log.Printf("Warning: Failed to stop network blocker: %v", err)
		} else {
			log.Println("✓ Network blocker detached")
		}

		// Clean up app blocker
		if err := linux.StopBlocker(); err != nil {
			log.Printf("Warning: Failed to stop app blocker: %v", err)
		} else {
			log.Println("✓ App blocker detached")
		}

		log.Println("✓ Cleanup complete - internet restored!")
		os.Exit(0)
	}()

	// Start App Blocker (LSM)
	if err := linux.StartBlocker(); err != nil {
		log.Fatalf("Failed to start app blocker: %v", err)
	}
	log.Println("✓ App blocker started")

	// Start Network Blocker (TC)
	if err := linux.StartNetworkBlocker("wlp1s0"); err != nil {
		log.Fatalf("Failed to start network blocker: %v", err)
	}
	log.Println("✓ Network blocker attached to wlp1s0")

	// Load policy and apply initial rules
	if err := core.ReloadPolicy("policy.json"); err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}
	log.Println("✓ Policy loaded")

	// Add initial allowed IPs from policy
	policy := core.GetPolicy()
	for _, ip := range policy.AllowedIPs {
		if err := linux.AllowIP(ip); err != nil {
			log.Printf("Warning: Failed to allow IP %s: %v", ip, err)
		} else {
			log.Printf("✓ Allowed IP: %s", ip)
		}
	}

	// Start audit logger in background
	go core.StartLogger()

	// Start DNS proxy (blocks here)
	log.Println("✓ Starting DNS proxy on 127.0.0.1:8053")
	core.StartDNSProxy()
}

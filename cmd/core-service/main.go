package main

import (
	"iicpc-network/adapters/linux"
	"iicpc-network/core"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// shutdown handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\n Shutting down...")
		if err := linux.StopNetworkBlocker(); err != nil {
			log.Printf("Warning: Failed to stop network blocker: %v", err)
		} else {
			log.Println("Network blocker detached")
		}

		// Clean up app blocker
		if err := linux.StopBlocker(); err != nil {
			log.Printf("Warning: Failed to stop app blocker: %v", err)
		} else {
			log.Println("App blocker detached")
		}

		log.Println("Cleanup complete - internet restored!")
		os.Exit(0)
	}()

	// starting app blocker (LSM hook)
	log.Println("Attempting to start app blocker...")
	if err := linux.StartBlocker(); err != nil {
		log.Fatalf("Failed to start app blocker: %v", err)
	}
	log.Println("App blocker started")

	// load policy BEFORE starting network blocker
	log.Println("Loading policy...")
	if err := core.ReloadPolicy("policy.json"); err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}
	log.Println("Policy loaded")

	// verify map contents
	log.Println("Verifying map contents...")
	if err := linux.DebugAllowedMap(); err != nil {
		log.Printf("Warning: Could not debug map: %v", err)
	}

	log.Println("Pre-resolving critical domains...")
	criticalDomains := []string{
		"docs.google.com",
		"drive.google.com",
		"codeforces.com",
		"www.codeforces.com",
		"m1.codeforces.com",
		"m2.codeforces.com",
		"m3.codeforces.com",
		"api.codeforces.com",
		"userpic.codeforces.org",
	}

	for _, domain := range criticalDomains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Printf("Warning: Failed to resolve %s: %v", domain, err)
			continue
		}
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				if err := linux.AllowIP(ipv4.String()); err != nil {
					log.Printf("Warning: Failed to allow IP %s for %s: %v", ipv4, domain, err)
				} else {
					log.Printf("Pre-allowed IP: %s (%s)", ipv4, domain)
				}
			}
		}
	}

	// add initial allowed IPs from policy
	policy := core.GetPolicy()
	for _, ip := range policy.AllowedIPs {
		if err := linux.AllowIP(ip); err != nil {
			log.Printf("Warning: Failed to allow IP %s: %v", ip, err)
		} else {
			log.Printf("Allowed IP: %s", ip)
		}
	}

	// NOW start Network Blocker (TC) - AFTER resolving domains
	log.Println("Starting network blocker...")
	if err := linux.StartNetworkBlocker("wlp1s0"); err != nil {
		if linux.IsUnsupported(err) {
			log.Println("Network blocker not supported on this interface/driver")
			log.Println("Continuing without network enforcement")
		} else {
			log.Printf("Network blocker failed: %v", err)
		}
	} else {
		log.Println(" Network blocker attached to wlp1s0")
	}

	// start audit logger in background
	go core.StartLogger()

	// start DNS proxy(blocks here)
	log.Println("Starting DNS proxy on 127.0.0.1:8053")
	core.StartDNSProxy()
}

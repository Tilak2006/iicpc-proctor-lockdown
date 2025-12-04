package main

import (
	"iicpc-network/adapters/linux"
	"iicpc-network/core"
	"log"
)

func main() {

	if err := linux.StartBlocker(); err != nil {
		log.Fatalf("Failed to start blocker: %v", err)
	}

	if err := core.ReloadPolicy("policy.json"); err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}

	go core.StartLogger()

	core.StartDNSProxy()
}

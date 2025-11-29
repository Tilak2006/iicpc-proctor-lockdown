package main

import (
	"iicpc-network/core"
	"log"
)

func main() {

	if err := core.ReloadPolicy("policy.json"); err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}

	go core.StartLogger()

	core.StartDNSProxy()
}

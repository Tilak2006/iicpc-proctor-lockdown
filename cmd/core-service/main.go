package main

import (
	"iicpc-network/core"
	"log"
)

func main() {

	if _, err := core.LoadPolicy("../../policy.json"); err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}

	go core.StartLogger()

	core.StartDNSProxy()
}

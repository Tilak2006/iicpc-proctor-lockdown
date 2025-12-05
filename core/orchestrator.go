package core

import (
	"fmt"
	"iicpc-network/adapters/linux"
)

func ApplyPolicy(p *Policy) error {
	if err := linux.SyncAllowedApps(p.AllowedApps); err != nil {
		return fmt.Errorf("sync blocked apps: %w", err)
	}

	// Future: enforce network blocking
	// When we build the TC filter later, we will call linux.SyncNetworkRules(p) here.

	return nil
}

package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

var currentPolicy atomic.Value

func init() {
	currentPolicy.Store(&Policy{})
}

type Policy struct {
	AllowedDomains []string `json:"allowed_domains"`
	AllowedApps    []string `json:"allowed_apps"`
	AllowedIPs     []string `json:"allowed_ips"`
}

func GetPolicy() *Policy {
	return currentPolicy.Load().(*Policy)
}

func ReloadPolicy(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(content, &p); err != nil {
		return fmt.Errorf("unmarshal policy json: %w", err)
	}

	currentPolicy.Store(&p)

	if err := ApplyPolicy(&p); err != nil {
		return fmt.Errorf("apply policy: %w", err)
	}

	return nil
}

func (p *Policy) IsAllowedDomain(domain string) bool {

	for _, d := range p.AllowedDomains {
		if d == domain {
			return true
		}
		if strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

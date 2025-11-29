package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

var currentPolicy *Policy
var policyMutex sync.RWMutex

// `...` -> takes the JSON format and feeds it into the Golang's CamelCase variable.
type Policy struct {
	AllowedDomains []string `json:"allowed_domains"`
	AllowedApps    []string `json:"allowed_apps"`
	AllowedIPs     []string `json:"allowed_ips"`
}

func (p *Policy) IsAllowedDomain(domain string) bool {
	for _, d := range p.AllowedDomains {
		if strings.HasSuffix(domain, d) {
			return true
		}
	}
	return false
}

func GetPolicy() *Policy {
	policyMutex.RLock()
	defer policyMutex.RUnlock()
	return currentPolicy
}

func LoadPolicy(path string) (*Policy, error) {

	content, err := os.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(content, &p); err != nil {
		return nil, fmt.Errorf("unmarshal policy json: %w", err)
	}

	return &p, nil
}

func ReloadPolicy(path string) error {
	newPolicy, err := LoadPolicy(path)
	if err != nil {
		return err
	}

	policyMutex.Lock()
	currentPolicy = newPolicy
	defer policyMutex.Unlock()

	return nil
}

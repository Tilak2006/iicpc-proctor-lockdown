package core

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp int64  `json:"ts"`
	ClientIP  string `json:"client_ip"`
	Domain    string `json:"domain"`
	Allowed   bool   `json:"allowed"`
}

var auditPool = sync.Pool{
	New: func() interface{} {
		return &AuditEntry{}
	},
}

func LogToDisk(ip, domain string, allowed bool, filename string) error {
	// borrows the generic item (interface{}) from auditPool
	v := auditPool.Get()

	// this tells the compiler "Trust me, this box contains an *AuditEntry"
	entry := v.(*AuditEntry)

	entry.Timestamp = time.Now().Unix()
	entry.ClientIP = ip
	entry.Domain = domain
	entry.Allowed = allowed

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Even if writing fails, we MUST still return the struct to the pool!
		resetAndPutBack(entry)
		return fmt.Errorf("failed to open audit log: %w", err)
	}

	// Create a JSON encoder and write the line
	if err := json.NewEncoder(f).Encode(entry); err != nil {
		f.Close()
		resetAndPutBack(entry)
		return fmt.Errorf("failed to write audit log: %w", err)
	}
	f.Close()

	// D. Clean & Return: Reset fields and put back in the pool
	resetAndPutBack(entry)
	return nil

}

func resetAndPutBack(entry *AuditEntry) {
	entry.ClientIP = ""
	entry.Domain = ""
	entry.Timestamp = 0
	entry.Allowed = false

	auditPool.Put(entry)
}

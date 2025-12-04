package core

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp int64  `json:"ts"`
	ClientIP  string `json:"client_ip"`
	Domain    string `json:"domain"`
	Allowed   bool   `json:"allowed"`
}

// auditPool reduces GC pressure as it recycles AuditEntry structs
var auditPool = sync.Pool{
	New: func() interface{} {
		return &AuditEntry{}
	},
}

// WriteLog serializes a log entry to the provided writer using a pooled struct
func WriteLog(w io.Writer, ip, domain string, allowed bool) error {
	v := auditPool.Get()
	entry := v.(*AuditEntry)

	entry.Timestamp = time.Now().Unix()
	entry.ClientIP = ip
	entry.Domain = domain
	entry.Allowed = allowed

	// encoding directly to the open stream
	if err := json.NewEncoder(w).Encode(entry); err != nil {
		resetAndPutBack(entry)
		return err
	}

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

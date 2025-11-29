package core

import (
	"bytes"
	"encoding/json"
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
	New: func() any {
		return &AuditEntry{}
	},
}

var bufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

var auditChan = make(chan []byte, 100_000)

func NewAuditEntry() *AuditEntry {
	e := auditPool.Get().(*AuditEntry)
	return e
}

func ReleaseAuditEntry(e *AuditEntry) {
	*e = AuditEntry{}
	auditPool.Put(e)
}

func logAudit(clientIP, domain string, allowed bool) {
	e := NewAuditEntry()
	e.Timestamp = time.Now().UnixNano()
	e.ClientIP = clientIP
	e.Domain = domain
	e.Allowed = allowed

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()

	json.NewEncoder(buf).Encode(e)

	ReleaseAuditEntry(e)

	// send to writer — never block
	select {
	case auditChan <- buf.Bytes():
	default:
	}

}

func StartAuditWriter(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	go func() {
		defer f.Close()

		batch := make([][]byte, 0, 4096)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case entry := <-auditChan:
				batch = append(batch, entry)

				if len(batch) >= 4096 {
					flushBatch(f, batch)
					batch = batch[:0]
				}

			case <-ticker.C:
				if len(batch) > 0 {
					flushBatch(f, batch)
					batch = batch[:0]
				}
			}
		}
	}()

	return nil
}

func flushBatch(f *os.File, batch [][]byte) {
	for _, b := range batch {
		f.Write(b)
		buf := bufferPool.Get().(*bytes.Buffer)
		buf.Reset()
		buf.Write(b)
		bufferPool.Put(buf)
	}
}

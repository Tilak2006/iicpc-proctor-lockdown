package core

import (
	"log"
	"net"
	"os"
	"strings"

	"iicpc-network/adapters/linux"

	"github.com/miekg/dns"
)

type LogRequest struct {
	ClientIP string
	Domain   string
	Allowed  bool
}

var logChannel = make(chan LogRequest, 1000)

func StartLogger() {
	f, err := os.OpenFile("audit.json.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open audit log: %v", err)
	}
	defer f.Close()

	for req := range logChannel {
		if err := WriteLog(f, req.ClientIP, req.Domain, req.Allowed); err != nil {
			log.Printf("Error writing audit log: %v", err)
		}
	}
}

func StartDNSProxy() {
	dns.HandleFunc(".", handleDNS)

	server := &dns.Server{Addr: "127.0.0.1:8053", Net: "udp"}
	log.Println("DNS Proxy started on 127.0.0.1:8053")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DNS Server failed: %v\n", err)
	}
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)

	if len(r.Question) == 0 {
		w.WriteMsg(&msg)
		return
	}

	rawQ := r.Question[0].Name
	q := strings.TrimSuffix(rawQ, ".")

	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	if !GetPolicy().IsAllowedDomain(q) {
		msg.Rcode = dns.RcodeNameError
		logChannel <- LogRequest{ClientIP: clientIP, Domain: q, Allowed: false}
		w.WriteMsg(&msg)
		return
	}

	logChannel <- LogRequest{ClientIP: clientIP, Domain: q, Allowed: true}

	c := new(dns.Client)
	resp, _, err := c.Exchange(r, "8.8.8.8:53")
	if err != nil {
		log.Printf("Upstream DNS error: %v\n", err)
		w.WriteMsg(&msg)
		return
	}

	for _, answer := range resp.Answer {
		if a, ok := answer.(*dns.A); ok {
			_ = linux.AllowIP(a.A.String())
		}
	}

	w.WriteMsg(resp)
}

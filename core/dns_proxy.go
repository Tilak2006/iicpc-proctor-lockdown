package core

import (
	"log"

	"github.com/miekg/dns"
)

var allowedDomains = []string{
	"codeforces.com.",
	"www.codeforces.com.",
	"iicpc.com.",
	"www.iicpc.com.",
}

func isAllowedDomain(q string) bool {
	for _, d := range allowedDomains {
		if q == d {
			return true
		}
	}
	return false
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)

	if len(r.Question) == 0 {
		w.WriteMsg(&msg)
		return
	}

	q := r.Question[0].Name

	if !isAllowedDomain(q) {
		msg.Rcode = dns.RcodeNameError
		log.Printf("Blocked DNS: %s\n", q)
		w.WriteMsg(&msg)
		return
	}

	c := new(dns.Client)
	resp, _, err := c.Exchange(r, "8.8.8.8:53")
	if err != nil {
		log.Printf("DNS error: %v\n", err)
		w.WriteMsg(&msg)
		return
	}

	w.WriteMsg(resp)
}

func StartDNSProxy() {
	dns.HandleFunc(".", handleDNS)

	server := &dns.Server{Addr: "127.0.0.1:53", Net: "udp"}

	log.Println("DNS Proxy started on 127.0.0.1:53")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DNS Server failed: %v\n", err)
	}
}

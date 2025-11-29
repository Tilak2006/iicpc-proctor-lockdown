package core

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

var logChannel = make(chan string)

func StartLogger() {
	for {
		domain := <-logChannel
		log.Printf("Blocked DNS: %s\n", domain)
	}
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)

	if len(r.Question) == 0 {
		w.WriteMsg(&msg)
		return
	}

	q := r.Question[0].Name

	if !GetPolicy().IsAllowedDomain(q) {
		msg.Rcode = dns.RcodeNameError

		logChannel <- fmt.Sprintf("dns_block:%s", q)

		w.WriteMsg(&msg)
		return
	}

	c := new(dns.Client)

	// sends request to googles public dns server to check
	resp, _, err := c.Exchange(r, "8.8.8.8:53")

	if err != nil {
		log.Printf("DNS error: %v\n", err)

		//instead of keeping the user waiting with a slow spinner, this fails the code immediately if err occurs.
		w.WriteMsg(&msg)

		return
	}

	w.WriteMsg(resp)
}

func StartDNSProxy() {
	dns.HandleFunc(".", handleDNS)

	// starts the server on port 8053
	server := &dns.Server{Addr: "127.0.0.1:8053", Net: "udp"}

	log.Println("DNS Proxy started on 127.0.0.1:8053")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DNS Server failed: %v\n", err)
	}
}

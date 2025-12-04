package core

import (
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

type LogRequest struct {
	ClientIP string
	Domain   string
	Allowed  bool
}

var logChannel = make(chan LogRequest, 1000)

func StartLogger() {
	// loops over every request coming down the channel
	for req := range logChannel {
		err := LogToDisk(req.ClientIP, req.Domain, req.Allowed, "audit.json.log")
		if err != nil {
			log.Printf("Error writing audit log: %v", err)
		}
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

		logChannel <- LogRequest{
			ClientIP: clientIP,
			Domain:   q,
			Allowed:  false,
		}

		w.WriteMsg(&msg)
		return
	}

	logChannel <- LogRequest{
		ClientIP: clientIP,
		Domain:   q,
		Allowed:  true,
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

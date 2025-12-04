//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "GPL";

// 1. The Map: Allowed Destination IPs
// Key: IPv4 Address (__u32) e.g., 1.1.1.1
// Value: 1 = Allowed
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} allowed_ips SEC(".maps");

// TC Action codes
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// 2. The Hook: Egress (Outgoing Traffic)
SEC("classifier")
int egress_filter(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;

    // Safety 1: Check Ethernet Header size
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    // We only filter IP packets (0x0800). Pass everything else (ARP, IPv6).
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    // Safety 2: Check IP Header size
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u32 dest_ip = ip->daddr;

    bpf_printk("Net Packet: dest=%x\n", dest_ip);

    // --- SAFETY NET: ALWAYS ALLOW LOCALHOST (127.x.x.x) ---
    // 127.0.0.1 is 0x0100007F in hex (Little Endian)
    // Actually, let's just allow traffic to ourselves to be safe.
    if (dest_ip == 0x0100007F) { 
        return TC_ACT_OK; 
    }

    // 3. Lookup: Is the destination IP allowed?
    __u32 *rule = bpf_map_lookup_elem(&allowed_ips, &dest_ip);
    if (rule) {
        return TC_ACT_OK; // Yes, allowed!
    }

    // 4. Default: DROP
    // bpf_printk("Blocking packet to IP: %x\n", dest_ip);
    return TC_ACT_SHOT;
}
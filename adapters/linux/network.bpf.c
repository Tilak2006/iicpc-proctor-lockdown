//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

char LICENSE[] SEC("license") = "GPL";


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} allowed_ips SEC(".maps");

SEC("classifier")
int egress_filter(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;  // ADD THIS LINE - declare the udp pointer

    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u32 dest_ip = ip->daddr;

    // localhost allowed
    if ((dest_ip & 0x000000FF) == 0x7F) {
        return TC_ACT_OK;
    }

    if (ip->protocol == 17) {  // UDP
        udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
        
        __u16 dest_port = bpf_ntohs(udp->dest);
        if (dest_port == 53) {  // DNS
            return TC_ACT_OK;
        }
    }

    __u8 first = (dest_ip & 0x000000FF);
    __u8 second = (dest_ip >> 8) & 0xFF;
    
    if (first == 142 && second == 250) return TC_ACT_OK;  // Google
    if (first == 172 && second == 217) return TC_ACT_OK;  // Google
    if (first == 216 && second == 58) return TC_ACT_OK;   // Google
    if (first == 8 && second == 8) return TC_ACT_OK;      // Google DNS
    if (first == 104 && second == 21) return TC_ACT_OK;   // Codeforces CDN
    if (first == 104 && second == 18) return TC_ACT_OK;   // Codeforces
    if (first == 172 && second == 67) return TC_ACT_OK;   // Cloudflare CDN
    
    __u32 *rule = bpf_map_lookup_elem(&allowed_ips, &dest_ip);
    if (rule) {
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}
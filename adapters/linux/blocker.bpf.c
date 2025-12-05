//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Rename to allowed_apps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, __u32);
} allowed_apps SEC(".maps");

// Helper to extract basename and lowercase
static __always_inline void process_filename(const char *path, char *out) {
    int i, last_slash = -1;
    char c;
    
    // Find last '/' in path (max 256 chars)
    #pragma unroll
    for (i = 0; i < 256; i++) {
        if (bpf_probe_read_kernel(&c, 1, path + i) < 0)
            break;
        if (c == '\0')
            break;
        if (c == '/')
            last_slash = i;
    }
    
    // Copy filename after last slash, converting to lowercase
    int start = last_slash + 1;
    #pragma unroll
    for (i = 0; i < 15; i++) {  // Leave room for null terminator
        if (bpf_probe_read_kernel(&c, 1, path + start + i) < 0)
            break;
        if (c == '\0')
            break;
        
        // Convert to lowercase
        if (c >= 'A' && c <= 'Z')
            c = c + 32;
        
        out[i] = c;
    }
    out[i] = '\0';
}

SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm) {
    char comm[16] = {0};
    
    // Read filename pointer
    const char *filename = BPF_CORE_READ(bprm, filename);
    if (!filename)
        return 0;
    
    // Extract basename and lowercase
    process_filename(filename, comm);
    
    // Check if in ALLOWED list
    __u32 *rule = bpf_map_lookup_elem(&allowed_apps, comm);
    
    // NOT in allowed list → BLOCK
    if (!rule) {
        bpf_printk("BLOCKED: %s\n", comm);
        return -13;  // -EACCES
    }
    
    // In allowed list → ALLOW
    bpf_printk("ALLOWED: %s\n", comm);
    return 0;
}


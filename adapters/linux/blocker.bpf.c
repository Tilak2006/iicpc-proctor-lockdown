//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// The map where the user-space side (Golang) tells what to block
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);   // takes the name of the blocked site (eg: chatgpt)
    __type(value, __u32);   // number of sites blocked (blocked = 1)
} blocked_apps SEC(".maps");


// We use LSM (Linux Security Module) because it allows us to return an error (-EPERM) and this is what gets exec before the OS calls a new program
SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm) {
    char comm[16] = {0};
    
    // We use bpf_probe_read_kernel_str to safely copy it from the struct
    long len = bpf_probe_read_kernel_str(comm, sizeof(comm), bprm->filename);
    if (len <= 0) {
        return 0;
    }

    bpf_printk("Checking exec: %s\n", comm);

    // Look it up in our Block List
    __u32 *rule = bpf_map_lookup_elem(&blocked_apps, comm);
    if (rule && *rule == 1) {
        // Return -EPERM (Operation not permitted) to stop it
        bpf_printk("Blocking execution of: %s\n", comm);
        return -1; // -EPERM
    }
    return 0; 
}

char LICENSE[] SEC("license") = "GPL";
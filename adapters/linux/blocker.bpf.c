//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, __u32);
} blocked_apps SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm) {
    char comm[16] = {0};
    
    long len = bpf_probe_read_kernel_str(comm, sizeof(comm), bprm->filename);
    if (len <= 0) {
        return 0;
    }

    __u32 *rule = bpf_map_lookup_elem(&blocked_apps, comm);
    if (rule && *rule == 1) {
        bpf_printk("Blocking execution: %s\n", comm);
        return -13; 
    }

    return 0; 
}
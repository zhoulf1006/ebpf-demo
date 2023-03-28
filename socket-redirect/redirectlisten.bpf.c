// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "redirectmap.h"

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, struct sock_key);
	__type(value, struct sock_info);
	__uint(max_entries, 1024);
} socks SEC(".maps");

SEC("kprobe/tcp_v4_listen")
int kprobe__tcp_v4_listen(struct pt_regs *ctx)
{
    struct bpf_sock_ops *skops = NULL;
    struct bpf_sock_tuple key = {};
    struct bpf_sock_tuple_info info = {};

    skops = (struct bpf_sock_ops *)PT_REGS_PARM1(ctx);
    bpf_memcpy(&key.src_ip, &skops->local_ip, sizeof(key.src_ip));
    bpf_memcpy(&key.src_port, &skops->local_port, sizeof(key.src_port));

    info.local_storage = &skops->local_storage;
    info.peer_storage = &skops->peer_storage;

    bpf_sock_map_update(&socks, &key, &info, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

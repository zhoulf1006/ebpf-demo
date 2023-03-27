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

SEC("kprobe/inet_csk_accept")
int kprobe__inet_csk_accept(struct pt_regs *ctx)
{
struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
struct sock_key key = {};
struct sock_info info = {};

if (!sock->sk)
	return 0;

key.src_ip = 0;
key.dst_ip = sk->__sk_common.skc_daddr;
key.src_port = 0;
key.dst_port = sk->__sk_common.skc_dport;

info.sock_addr = (unsigned long)sock;

bpf_sock_map_update(&socks, &key, &info, BPF_ANY);

return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

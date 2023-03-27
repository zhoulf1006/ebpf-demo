// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "redirectmap.h"

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx)
{
struct msghdr *msg = (struct msghdr *)PT_REGS_PARM1(ctx);
struct sock_key key = {};
struct sock_info *info;
struct sockaddr_in *sin;
int i;

// Find destination IP and port from msg
for (i = 0; i < msg->msg_namelen; i += sizeof(*sin)) {
	sin = (struct sockaddr_in *)&msg->msg_name[i];
	if (sin->sin_family == AF_INET) {
		key.dst_ip = sin->sin_addr.s_addr;
		key.dst_port = sin->sin_port;
		break;
	}
}

// Lookup socket pair in map
info = bpf_sock_map_lookup(&socks, &key, sizeof(key), 0);
if (!info)
	return 0;

// Redirect sendmsg to other socket
return bpf_redirect(info->sock_addr, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

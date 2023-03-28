/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __REDIRECTMAP_H
#define __REDIRECTMAP_H

#include "vmlinux.h"
// #include <linux/in.h>
// #include <linux/types.h>

struct sock_key {
__u32 src_ip;
__u32 dst_ip;
__u16 src_port;
__u16 dst_port;
};

struct sock_info {
__u64 sock_addr;
};

#endif /* __REDIRECTMAP_H */
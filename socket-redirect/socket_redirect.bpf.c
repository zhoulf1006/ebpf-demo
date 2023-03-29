#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "socket_redirect.h"

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, struct sock *);
} sock_ops_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ring_buffer_map SEC(".maps");

static __always_inline void output_connection_info(void *ctx, struct sock_key *key) {
    struct connection_info conn_info = {};
    conn_info.sip4 = key->sip4;
    conn_info.dip4 = key->dip4;
    conn_info.sport = key->sport;
    conn_info.dport = key->dport;

    bpf_ringbuf_output(&ring_buffer_map, &conn_info, sizeof(conn_info), BPF_RB_FORCE_WAKEUP);
}

SEC("sockops")
int sock_map_update(struct bpf_sock_ops *skops) {
    struct sock_key key = {};
    struct sock *sk;
    int op;

    sk = (struct sock *)skops->sk;
    if (!sk)
        return 0;

    op = (int)skops->op;

    key.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    key.sip4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.dip4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
        output_connection_info(skops, &key);
    } else if (op == BPF_SOCK_OPS_STATE_CB) {
        int state = skops->args[0];

        if (state == TCP_CLOSE) {
            bpf_map_delete_elem(&sock_ops_map, &key);
        }
    }

    return 0;
}

SEC("sk_msg")
int sendmsg_prog(struct sk_msg_md *msg) {
    struct sock_key key = {};
    struct sock *sk;

    key.family = msg->family;
    key.sip4 = msg->local_ip4;
    key.sport = msg->local_port;
    key.dip4 = msg->remote_ip4;
    key.dport = msg->remote_port;

    sk = bpf_map_lookup_elem(&sock_ops_map, &key);
    if (!sk) {
        output_connection_info(msg, &key);
        return SK_PASS;
    }

    return bpf_sk_redirect_map((struct __sk_buff *)msg->sk, &sock_ops_map, (unsigned long)&key, BPF_F_INGRESS);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;

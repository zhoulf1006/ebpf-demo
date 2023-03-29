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

SEC("sockops")
int sock_map_update(struct bpf_sock_ops *skops) {
    struct sock_key key = {};
    struct sock *sk;
    int op;

    sk = (struct sock *)skops->sk;
    if (!sk)
        return 0;

    op = (int)skops->op;

    // key.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    // key.sip4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    // key.dip4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    // key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    // key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key.family = sk->sk_family;
    key.sip4 = sk->sk_rcv_saddr;
    key.sport = sk->sk_num;
    key.dip4 = sk->sk_daddr;
    key.dport = sk->sk_dport;

    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    } else if (op == BPF_SOCK_OPS_STATE_CB) {
        int state = skops->args[0];

        if (state == TCP_CLOSE) {
            bpf_map_delete_elem(&sock_ops_map, &key);
        }
    }

    return 0;
}

// SEC("sockops")
// int sock_map_update(struct bpf_sock_ops *skops) {
//     struct sock_key key = {};
//     struct sock *sk;
//     int op;

//     sk = (struct sock *)skops->sk;
//     if (!sk)
//         return 0;

//     op = (int)skops->op;

//     key.family = bpf_core_read(&sk->__sk_common.skc_family, sizeof(key.family));
//     key.sip4 = bpf_core_read(&sk->__sk_common.skc_rcv_saddr, sizeof(key.sip4));
//     key.dip4 = bpf_core_read(&sk->__sk_common.skc_daddr, sizeof(key.dip4));
//     key.sport = bpf_core_read(&sk->__sk_common.skc_num, sizeof(key.sport));
//     key.dport = bpf_core_read(&sk->__sk_common.skc_dport, sizeof(key.dport));

//     if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
//         bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
//     } else if (op == BPF_SOCK_OPS_STATE_CB) {
//         int state = skops->args[0];

//         if (state == TCP_CLOSE) {
//             bpf_map_delete_elem(&sock_ops_map, &key);
//         }
//     }

//     return 0;
// }

SEC("sk_msg")
int sendmsg_prog(struct sk_msg_md *msg) {
    struct sock_key key = {};
    struct sock *sk;
    __u32 key_hash;

    key.family = msg->family;
    key.sip4 = msg->local_ip4;
    key.sport = msg->local_port;
    key.dip4 = msg->remote_ip4;
    key.dport = msg->remote_port;

    sk = bpf_map_lookup_elem(&sock_ops_map, &key);
    if (!sk)
        return SK_PASS;

    key_hash = (__u32)(unsigned long)&key;
    return bpf_sk_redirect_map((struct __sk_buff *)msg->sk, &sock_ops_map, key_hash, BPF_F_INGRESS);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;

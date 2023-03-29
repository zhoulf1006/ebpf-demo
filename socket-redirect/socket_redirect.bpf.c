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

    key.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    key.sip4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.dip4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    } else if (op == BPF_SOCK_OPS_TCP_CLOSE) {
        bpf_sock_hash_del(&sock_ops_map, &key);
    }

    return 0;
}

SEC("cgroup/sendmsg")
int sendmsg_prog(struct bpf_sock_addr *ctx) {
    struct sock_key key = {};
    struct bpf_sock *sk;
    void *msg_name;

    key.sip4 = ctx->user_ip4;
    key.family = ctx->family;
    key.sport = ctx->user_port;

    msg_name = BPF_CORE_READ(ctx->msg, msg_name);
    if (msg_name) {
        key.dip4 = BPF_CORE_READ((struct sockaddr_in *)msg_name, sin_addr.s_addr);
        key.dport = BPF_CORE_READ((struct sockaddr_in *)msg_name, sin_port);
    } else {
        return SK_PASS;
    }

    sk = bpf_map_lookup_elem(&sock_ops_map, &key);
    if (!sk)
        return SK_PASS;

    return bpf_sk_redirect_map(ctx, &sock_ops_map, &key, BPF_F_INGRESS);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
